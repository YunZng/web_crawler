import logging
import re
import sys
from bs4 import BeautifulSoup
from queue import Queue
from urllib import parse, request

logging.basicConfig(level=logging.DEBUG, filename='output.log', filemode='w')
visitlog = logging.getLogger('visited')
extractlog = logging.getLogger('extracted')


def parse_links(root, html):
    soup = BeautifulSoup(html, 'html.parser')
    for link in soup.find_all('a'):
        href = link.get('href')
        if href:
            text = link.string
            if not text:
                text = ''
            text = re.sub('\s+', ' ', text).strip()
            yield (parse.urljoin(root, link.get('href')), text)


def parse_links_sorted(root, html):
    # TODO: implement
    return []


def get_links(url):
    res = request.urlopen(url)
    return list(parse_links(url, res.read()))


def get_nonlocal_links(url):
    p_url = parse.urlparse(url)
    links = get_links(url)
    filtered = []
    for (link, title) in links:
        p_link = parse.urlparse(parse.urljoin(url, link))
        if not p_link.netloc == p_url.netloc or (p_link.netloc == p_url.netloc and not p_link.path.rstrip('/') == p_url.path.rstrip('/')):
            filtered.append((link, title))
    return filtered


def crawl(root:str, wanted_content=['text/html; charset=UTF-8'], within_domain=True):
    '''Crawl the url specified by `root`.
    `wanted_content` is a list of content types to crawl
    `within_domain` specifies whether the crawler should limit itself to the domain of `root`
    '''
    # TODO: implement

    queue = Queue()
    queue.put(root)
    root_domain = parse.urlparse(root).netloc

    visited = []
    extracted = []

    cnt = 0
    while not queue.empty():
        if cnt == 200:
            break
        cnt+=1
        url = queue.get()
        if not url in visited:
            try:
                # default GET request object, change to HEAD request object, avoids requesting unnecessary things
                req_obj = request.Request(url, method='HEAD')
                req = request.urlopen(req_obj)
                if not req.headers['Content-Type'] in wanted_content:
                    continue
                req = request.urlopen(url)
                html = req.read()

                visited.append(url)
                visitlog.debug(url)
                for ex in extract_information(url, html):
                    extracted.append(ex)
                    extractlog.debug(ex)

                for link, title in get_nonlocal_links(url):
                    if within_domain and not parse.urlparse(link).netloc == root_domain:
                        continue
                    queue.put(link)

            except Exception as e:
                print(e, url)

    return visited, extracted


def extract_information(address, html):
    '''Extract contact information from html, returning a list of (url, category, content) pairs,
    where category is one of PHONE, ADDRESS, EMAIL'''

    # TODO: implement
    results = []
    for match in re.findall('\d\d\d-\d\d\d-\d\d\d\d', str(html)):
        results.append((address, 'PHONE', match))
    return results


def writelines(filename, data):
    with open(filename, 'w') as fout:
        for d in data:
            print(d, file=fout)


def main():
    site = sys.argv[1]

    links = get_links(site)
    writelines('links.txt', links)

    nonlocal_links = get_nonlocal_links(site)
    writelines('nonlocal.txt', nonlocal_links)

    visited, extracted = crawl(site)
    writelines('visited.txt', visited)
    writelines('extracted.txt', extracted)


if __name__ == '__main__':
    main()