import io
import re
import time
import gzip
import json
import hashlib
import ipaddress
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse, urldefrag, quote
from urllib.robotparser import RobotFileParser
import socket

import pandas as pd
import requests
import streamlit as st
from bs4 import BeautifulSoup
from openpyxl.styles import Font

st.set_page_config(page_title='掲載URL収集ツール', layout='wide')
USER_AGENT = 'ListingAuditBot/1.0 (respectful site audit; contact your site administrator)'
TIMEOUT = 12
MAX_BYTES = 2_000_000
HEADERS = {'User-Agent': USER_AGENT, 'Accept': 'text/html,application/xml,text/xml;q=0.9,*/*;q=0.5'}


def host_of(url):
    try:
        return (urlparse(url).hostname or '').lower().rstrip('.')
    except ValueError:
        return ''


def normalize_host(raw):
    raw = str(raw).strip()
    if not raw or raw.lower() in ('nan', 'none'): return ''
    if not re.match(r'^https?://', raw, re.I): raw = 'https://' + raw
    h = host_of(raw)
    if h.startswith('www.'): h = h[4:]
    if not h or '.' not in h or h in {'google.co.jp', 'google.com'} or h.endswith('.google.com') or h.endswith('.google.co.jp'):
        return ''
    return h


def in_scope(host, domain):
    return host == domain or host.endswith('.' + domain)


def public_url(url, domain=None):
    try:
        p = urlparse(url)
        if p.scheme not in ('http', 'https') or not p.hostname or p.username or p.password: return False
        h = p.hostname.lower()
        if domain and not in_scope(h, domain): return False
        # Block private/reserved IPs and names that resolve to them (SSRF protection).
        addresses = socket.getaddrinfo(h, p.port or (443 if p.scheme == 'https' else 80), type=socket.SOCK_STREAM)
        if not addresses: return False
        return all(ipaddress.ip_address(a[4][0]).is_global for a in addresses)
    except (OSError, ValueError):
        return False


def safe_get(url, domain, session):
    if not public_url(url, domain): return None
    try:
        r = session.get(url, headers=HEADERS, timeout=TIMEOUT, allow_redirects=False, stream=True)
        if r.status_code in (301, 302, 303, 307, 308):
            location = r.headers.get('Location')
            r.close()
            if not location: return None
            target = urljoin(url, location)
            if not public_url(target, domain): return None
            r = session.get(target, headers=HEADERS, timeout=TIMEOUT, allow_redirects=False, stream=True)
        if r.status_code != 200: r.close(); return None
        typ = r.headers.get('Content-Type', '').lower()
        if not any(t in typ for t in ('html', 'xml', 'text/plain')): r.close(); return None
        raw = bytearray()
        for chunk in r.iter_content(65536):
            raw.extend(chunk)
            if len(raw) > MAX_BYTES: r.close(); return None
        r._content = bytes(raw)
        return r
    except requests.RequestException:
        return None


def allowed(url, robots):
    try: return robots.can_fetch(USER_AGENT, url)
    except Exception: return False


def load_robots(base, domain, session):
    robots = RobotFileParser()
    url = base + '/robots.txt'
    response = safe_get(url, domain, session)
    if response is None:
        # Fail closed if robots rules cannot be retrieved.
        return None, []
    lines = response.text.splitlines()
    robots.parse(lines)
    maps = [line.split(':', 1)[1].strip() for line in lines if line.lower().startswith('sitemap:')]
    return robots, maps


def sitemap_urls(base, domain, session, robots, extra_maps, max_pages):
    queue = deque(dict.fromkeys(extra_maps + [base + '/sitemap.xml']))
    visited = set()
    results = []
    while queue and len(visited) < 25 and len(results) < max_pages:
        url = queue.popleft()
        if url in visited or not public_url(url, domain) or not allowed(url, robots): continue
        visited.add(url)
        r = safe_get(url, domain, session)
        if r is None: continue
        try:
            soup = BeautifulSoup(r.content, 'xml')
            for loc in soup.find_all('loc'):
                link = loc.get_text(strip=True)
                if not link or not in_scope(host_of(link), domain): continue
                if loc.parent and loc.parent.name.lower() == 'sitemap':
                    if link not in visited: queue.append(link)
                elif loc.parent and loc.parent.name.lower() == 'url':
                    results.append(link)
                    if len(results) >= max_pages: break
        except Exception:
            continue
    return list(dict.fromkeys(results))


def extract_site_name(soup, domain):
    """Best-effort site name, not article title; never invent a name."""
    for attrs in ({'property': 'og:site_name'}, {'name': 'application-name'},
                  {'name': 'apple-mobile-web-app-title'}):
        tag = soup.find('meta', attrs=attrs)
        if tag and tag.get('content', '').strip():
            return tag['content'].strip()[:120]
    if soup.title:
        title = soup.title.get_text(' ', strip=True)
        # Common article-title | site-name and article-title - site-name formats.
        for sep in (' | ', '｜', ' - ', ' – ', ' — ', '｜'):
            if sep in title:
                candidate = title.rsplit(sep, 1)[-1].strip()
                if candidate and len(candidate) <= 80:
                    return candidate
    return ''


def check_page(url, domain, session, robots, keyword, link_patterns):
    if not allowed(url, robots): return None, []
    r = safe_get(url, domain, session)
    if r is None or 'html' not in r.headers.get('Content-Type', '').lower(): return None, []
    soup = BeautifulSoup(r.content, 'html.parser')
    anchors = [(urljoin(r.url, a.get('href', '')), a.get_text(' ', strip=True)) for a in soup.find_all('a', href=True)]
    links = [href for href, _ in anchors]
    # パターン未指定時は「候補」のみ検出。ASPの中継先は検証しない。
    if link_patterns:
        matched_links = [href for href, _ in anchors if any(p.casefold() in href.casefold() for p in link_patterns)]
        link_status = 'パターン一致' if matched_links else 'なし'
    else:
        matched_links = [href for href, label in anchors if keyword and
                         (keyword.casefold() in label.casefold() or keyword.casefold() in href.casefold())]
        link_status = '候補・要確認' if matched_links else 'なし'
    for tag in soup(['script', 'style', 'noscript']): tag.decompose()
    text = soup.get_text(' ', strip=True)
    text_match = keyword.casefold() in text.casefold() if keyword else False
    return {'url': r.url, 'text_match': text_match, 'link_match': bool(matched_links),
            'link_status': link_status,
            'matched_links': ' | '.join(dict.fromkeys(matched_links))[:3000],
            'title': soup.title.get_text(' ', strip=True)[:200] if soup.title else '',
            'site_name': extract_site_name(soup, domain)}, links


def read_urls(upload):
    name = upload.name.lower()
    if name.endswith('.csv'):
        raw = upload.getvalue()
        for enc in ('utf-8-sig', 'cp932'):
            try: return pd.read_csv(io.BytesIO(raw), dtype=str, encoding=enc)
            except UnicodeDecodeError: pass
        raise ValueError('CSVの文字コードを読み取れません')
    return pd.read_excel(upload, dtype=str)


def excel_bytes(details, summary, errors, history):
    out = io.BytesIO()
    with pd.ExcelWriter(out, engine='openpyxl') as writer:
        for name, frame in [('掲載URL一覧', details), ('ドメイン別集計', summary), ('エラー一覧', errors), ('検索履歴', history)]:
            frame.to_excel(writer, sheet_name=name, index=False)
            ws = writer.sheets[name]
            ws.freeze_panes = 'A2'
            for row in ws.iter_rows():
                for cell in row:
                    cell.font = Font(name='Meiryo UI', size=10, bold=(cell.row == 1))
            ws.auto_filter.ref = ws.dimensions
            for col in ws.columns:
                letter = col[0].column_letter
                ws.column_dimensions[letter].width = min(65, max(15, max(len(str(cell.value or '')) for cell in list(col)[:100]) + 2))
    return out.getvalue()


st.title('🔎 掲載URL収集ツール')
st.markdown('''<style>
.stButton > button[kind="primary"] {background: linear-gradient(105deg,#2563eb,#7c3aed); color:white; border:0; border-radius:14px; min-height:3.4rem; font-size:1.08rem; font-weight:750; box-shadow:0 5px 15px rgba(67,56,202,.22);}
.stButton > button[kind="primary"]:hover {background:linear-gradient(105deg,#1d4ed8,#6d28d9); color:white; transform:translateY(-1px);}
</style>''', unsafe_allow_html=True)
st.caption('サイトマップ・サイト内リンクから候補を集め、ページ本文とリンクを検査します。検索APIは使用しません。網羅性は保証されません。')
st.subheader('URL一覧の入力')
input_method = st.radio('入力方法', ['ファイルをアップロード', 'テキストを直接貼り付け'], horizontal=True)
file = None
pasted = ''
if input_method == 'ファイルをアップロード':
    file = st.file_uploader('URL一覧（Excel / CSV）', type=['xlsx', 'csv'])
else:
    pasted = st.text_area('URL一覧を貼り付け（1行に1件）', height=180,
                          placeholder='https://example.com/page1\nhttps://www.example.org/page2')
    st.caption('ExcelのURL列をコピーして、そのまま貼り付けてもOK。空行は無視します。')
keyword = st.text_input('検索キーワード', value='楽天銀行スーパーローン')
mode = st.radio('掲載URLの検出条件', ['商品名の掲載', '送客リンクの掲載', '両方を検出'], index=2)
st.caption('送客リンクはリンクテキストまたはURLに検索キーワードが含まれるものを候補として抽出します（要確認）。')
max_pages = st.number_input('ドメインあたり最大確認ページ数', 10, 1000, 10, step=10)
delay = st.number_input('同一サイトへのアクセス間隔（秒）', 0.5, 10.0, 1.0, step=0.5)

raw_urls = []
if input_method == 'ファイルをアップロード' and file is not None:
    try:
        data = read_urls(file)
        columns = list(data.columns)
        url_col = st.selectbox('URLが入っている列', columns,
                               index=next((i for i,c in enumerate(columns) if 'url' in str(c).lower()), 0))
        raw_urls = data[url_col].dropna().tolist()
    except Exception as exc:
        st.error(f'入力ファイルの読込エラー: {exc}')
elif input_method == 'テキストを直接貼り付け' and pasted.strip():
    raw_urls = [line.strip() for line in pasted.splitlines() if line.strip()]

domains = list(dict.fromkeys(filter(None, (normalize_host(v) for v in raw_urls))))
if raw_urls:
    st.info(f'入力URL数: {len(raw_urls):,} 件 / 抽出ドメイン数: {len(domains):,} 件')
    with st.expander('ドメイン一覧を確認'):
        st.dataframe(pd.DataFrame({'サイト名': [st.session_state.get('site_names', {}).get(d, '') for d in domains], 'ドメイン': domains}), hide_index=True)
    domain_excel = io.BytesIO()
    with pd.ExcelWriter(domain_excel, engine='openpyxl') as writer:
        pd.DataFrame({'サイト名': [st.session_state.get('site_names', {}).get(d, '') for d in domains], 'ドメイン': domains}).to_excel(writer, index=False, sheet_name='ドメイン一覧')
        ws = writer.sheets['ドメイン一覧']
        ws.freeze_panes = 'A2'
        ws.auto_filter.ref = ws.dimensions
        ws.column_dimensions['A'].width = 35
        ws.column_dimensions['B'].width = 45
        for row in ws.iter_rows():
            for cell in row:
                cell.font = Font(name='Meiryo UI', size=10, bold=(cell.row == 1))
    st.download_button('📥 ドメイン一覧をダウンロード', domain_excel.getvalue(),
                       file_name='ドメイン一覧.xlsx',
                       mime='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                       on_click='ignore')

def collect_domain(domain, keyword, mode, max_pages, delay, settings_id, seed_urls):
    details, errors = [], []
    site_name = ''
    now = datetime.now(timezone.utc).isoformat(timespec='seconds')
    visited, checked, succeeded = set(), 0, 0
    session = requests.Session()  # ワーカー間でSessionを共有しない
    try:
        base = 'https://' + domain
        robots, maps = load_robots(base, domain, session)
        if robots is None:
            raise RuntimeError('robots.txtを確認できないため巡回をスキップしました')
        crawl_delay = robots.crawl_delay(USER_AGENT)
        actual_delay = max(float(delay), float(crawl_delay or 0))
        # サイトマップは候補収集専用。実際のページ確認は max_pages 以内。
        # 入力された掲載URLを最優先で検査。旧版で拾えたURLの取りこぼしを防ぐ。
        candidates = list(seed_urls) + sitemap_urls(base, domain, session, robots, maps, int(max_pages) * 3)
        candidates.append(base + '/')
        queued = set()
        frontier = []
        def add(url):
            url = urldefrag(url)[0]
            if url not in queued and url not in visited and in_scope(host_of(url), domain):
                queued.add(url)
                frontier.append(url)
        for url in candidates: add(url)
        last_request_at = 0.0
        while frontier and checked < max_pages:
            url = frontier.pop(0)
            if url in visited or not allowed(url, robots): continue
            visited.add(url)
            # 同一ドメインのページ確認間隔。異なるドメインは並列に進む。
            remaining = actual_delay - (time.monotonic() - last_request_at)
            if remaining > 0: time.sleep(remaining)
            last_request_at = time.monotonic()
            checked += 1
            page, links = check_page(url, domain, session, robots, keyword, [])
            if page:
                if not site_name and page.get('site_name'):
                    site_name = page['site_name']
                succeeded += 1
                match = ((mode == '商品名の掲載' and page['text_match']) or
                         (mode == '送客リンクの掲載' and page['link_match']) or
                         (mode == '両方を検出' and (page['text_match'] or page['link_match'])))
                if match:
                    details.append({'サイト名': site_name or page.get('site_name', ''), 'ドメイン': domain, 'URL': page['url'], 'タイトル': page['title'],
                                    '商品名掲載': '○' if page['text_match'] else '×',
                                    '送客リンク掲載': page['link_status'],
                                    '一致したリンク': page['matched_links'], '確認日時UTC': now,
                                    '設定ID': settings_id})
                for link in links: add(link)
        state = '完了' if checked else '確認ページなし'
    except Exception as exc:
        errors.append({'ドメイン': domain, 'URL': '', 'エラー': str(exc)})
        state = '失敗'
    finally:
        session.close()
    history = {'サイト名': site_name, 'ドメイン': domain, '設定ID': settings_id, '状態': state,
               '確認ページ数': checked, '取得成功ページ数': succeeded, '候補URL数': len(locals().get('frontier', [])) + len(visited), '検出URL数': len(details), '確認日時UTC': now}
    return details, errors, history


st.caption('ドメイン間は並列処理。入力URLを優先し、続いてサイトマップ・サイト内リンクを確認します。')
workers = 5  # 同時処理ドメイン数（UIには表示しない）
if st.button('🚀 掲載URLを収集する', type='primary', disabled=not domains, use_container_width=True):
    if not keyword.strip(): st.error('検索キーワードを入力してください。'); st.stop()
    settings_id = hashlib.sha256(json.dumps({'keyword': keyword, 'mode': mode}, ensure_ascii=False, sort_keys=True).encode()).hexdigest()[:16]
    st.session_state.pop('last_result', None)
    seed_map = {d: [] for d in domains}
    for raw in raw_urls:
        d = normalize_host(raw)
        if d in seed_map:
            candidate = str(raw).strip()
            if not re.match(r'^https?://', candidate, re.I): candidate = 'https://' + candidate
            if public_url(candidate, d) and candidate not in seed_map[d]: seed_map[d].append(candidate)
    progress = st.progress(0)
    status = st.empty()
    details, errors, history = [], [], []
    with ThreadPoolExecutor(max_workers=int(workers)) as pool:
        futures = {pool.submit(collect_domain, domain, keyword.strip(), mode, int(max_pages), float(delay), settings_id, seed_map[domain]): domain for domain in domains}
        for idx, future in enumerate(as_completed(futures), start=1):
            domain = futures[future]
            try:
                d, e, h = future.result()
                details.extend(d); errors.extend(e); history.append(h)
            except Exception as exc:
                errors.append({'ドメイン': domain, 'URL': '', 'エラー': str(exc)})
            progress.progress(idx / len(domains))
            status.write(f'完了 {idx}/{len(domains)} ドメイン（直近: {domain}）')
    df = pd.DataFrame(details, columns=['サイト名','ドメイン','URL','タイトル','商品名掲載','送客リンク掲載','一致したリンク','確認日時UTC','設定ID'])
    hdf = pd.DataFrame(history, columns=['サイト名','ドメイン','設定ID','状態','確認ページ数','取得成功ページ数','候補URL数','検出URL数','確認日時UTC'])
    summary = pd.DataFrame({'ドメイン': domains}).merge(df.groupby('ドメイン').size().rename('検出URL件数').reset_index(), how='left', on='ドメイン')
    name_map = dict(zip(hdf['ドメイン'], hdf['サイト名']))
    st.session_state['site_names'] = name_map
    summary.insert(0, 'サイト名', summary['ドメイン'].map(name_map).fillna(''))
    if not df.empty:
        df['サイト名'] = df['ドメイン'].map(name_map).fillna(df['サイト名'])
    summary['検出URL件数'] = summary['検出URL件数'].fillna(0).astype(int)
    edf = pd.DataFrame(errors, columns=['ドメイン','URL','エラー'])
    st.session_state['last_result'] = {
        'df': df, 'history': hdf, 'errors': edf, 'excel': excel_bytes(df, summary, edf, hdf),
        'filename': f'掲載URL収集結果_{datetime.now().strftime("%Y%m%d_%H%M")}.xlsx',
        'detected': len(details), 'error_count': len(errors),
    }
    st.balloons()

# ダウンロードによる再実行でも結果を消さず、次の収集開始まで保持する。
if 'last_result' in st.session_state:
    result = st.session_state['last_result']
    st.success(f"処理終了：今回の検出 {result['detected']} 件 / エラー {result['error_count']} 件")
    st.subheader('検索結果')
    st.caption('※ 入力URLを優先して確認します。検索結果が0件でもサイト全体に掲載がないことは意味しません。')
    st.dataframe(result['df'], hide_index=True, use_container_width=True)
    with st.expander('ドメイン別の確認状況（診断）'):
        st.dataframe(result['history'], hide_index=True, use_container_width=True)
    if not result['errors'].empty:
        with st.expander('エラー一覧'):
            st.dataframe(result['errors'], hide_index=True, use_container_width=True)
    domain_export = io.BytesIO()
    with pd.ExcelWriter(domain_export, engine='openpyxl') as writer:
        pd.DataFrame({'サイト名': [st.session_state.get('site_names', {}).get(d, '') for d in domains],
                      'ドメイン': domains}).to_excel(writer, index=False, sheet_name='ドメイン一覧')
        ws = writer.sheets['ドメイン一覧']
        ws.freeze_panes = 'A2'
        ws.auto_filter.ref = ws.dimensions
        ws.column_dimensions['A'].width = 35
        ws.column_dimensions['B'].width = 45
        for row in ws.iter_rows():
            for cell in row:
                cell.font = Font(name='Meiryo UI', size=10, bold=(cell.row == 1))
    st.download_button('📥 サイト名付きドメイン一覧をダウンロード', domain_export.getvalue(),
                       file_name='ドメイン一覧_サイト名付き.xlsx',
                       mime='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', on_click='ignore')
    st.download_button('📥 結果Excelをダウンロード', result['excel'],
                       file_name=result['filename'],
                       mime='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                       on_click='ignore')
    if result['error_count']:
        st.warning('一部処理できなかったドメインがあります。エラー一覧を確認してください。')
