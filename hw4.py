import logging
import re
import sys
from bs4 import BeautifulSoup
from queue import Queue
from queue import PriorityQueue
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
    '''Parse all links from html, returning a list of (url, relevance) pairs,
    where relevance is a score indicating the relevance of the link to the root URL'''
    # TODO: implement

    soup = BeautifulSoup(html, 'html.parser')
    links = soup.find_all('a') # Find all anchor tags in the html

    # Calculate a relevance score for each link based on the number of common path segments with the root URL
    root_path = parse.urlparse(root).path.split('/')
    link_scores = []
    for link in links:
        href = link.get('href')
        if href:
            # Parse the link URL and split its path into segments
            parsed_href = parse.urlparse(href)
            link_path = parsed_href.path.split('/')

            common_path_segments = sum([1 for i in range(min(len(root_path), len(link_path))) if root_path[i] == link_path[i]])
            relevance = common_path_segments / max(len(link_path), 1)

            link_scores.append((href, relevance))

    link_scores.sort(key=lambda x: x[1], reverse=True)
    return link_scores


def get_links(url):
    res = request.urlopen(url)
    return list(parse_links(url, res.read()))


def get_nonlocal_links(url):
    '''Get a list of links on the page specificed by the url,
    but only keep non-local links and non self-references.
    Return a list of (link, title) pairs, just like get_links()'''
    # TODO: implement

    p_url = parse.urlparse(url)
    links = get_links(url)
    filtered = []
    for (link, title) in links:
        # Task 1
        # if link is a path, urljoin can combine url and link to form a full link, useful for self-reference detection
        p_link = parse.urlparse(parse.urljoin(url, link))
        # netloc is domain
        # need to stip trailing '/', this issue came up on piazza
        if not p_link.netloc == p_url.netloc or (p_link.netloc == p_url.netloc and not p_link.path.rstrip('/') == p_url.path.rstrip('/')):
            filtered.append((link, title))
    return filtered


def crawl(root:str, wanted_content=['text/html; charset=UTF-8'], within_domain=True):
    '''Crawl the url specified by `root`.
    `wanted_content` is a list of content types to crawl
    `within_domain` specifies whether the crawler should limit itself to the domain of `root`
    '''
    # TODO: implement

    # queue = Queue()
    # queue.put(root)
    queue = PriorityQueue()
    queue.put((0, root))
    root_domain = parse.urlparse(root).netloc

    visited = []
    extracted = []

    cnt = 0
    while not queue.empty():
        if cnt == 200:
            break
        cnt+=1
        # url = queue.get()
        _, url = queue.get()
        
        # Task 2, avoid visited link
        if not url in visited:
            try:
                # Task 4
                # default GET request, change to HEAD request object, avoids requesting unnecessary things
                req_obj = request.Request(url, method='HEAD')
                # urlopen accepts request object and string url, here I passed the request object
                req = request.urlopen(req_obj)
                # if not desired content type skip iteration
                if not req.headers['Content-Type'] in wanted_content:
                    continue
                # this time I passed the string url, this is a GET request, you can read body content
                req = request.urlopen(url)
                html = req.read()

                visited.append(url)
                visitlog.debug(url)
                for ex in extract_information(url, html):
                    extracted.append(ex)
                    extractlog.debug(ex)

                # Task 2, avoid self-reference links using get_nonlocal_links
                nonlocal_links_set = set(link for link, _ in get_nonlocal_links(url))

                # for link, _ in get_nonlocal_links(url):
                for link, relevance in parse_links_sorted(url, html):
                    # Task 3, domain check
                    if within_domain and not parse.urlparse(link).netloc == root_domain:
                        continue
                    if link not in nonlocal_links_set:
                        continue
                        # queue.put(link)
                    queue.put((relevance, link))

            except Exception as e:
                print(e, url)

    return visited, extracted


def extract_information(address, html):
    '''Extract contact information from html, returning a list of (url, category, content) pairs,
    where category is one of PHONE, ADDRESS, EMAIL'''
    # TODO: implement

    results = []
    visited_match = []

    # Extract phone numbers
    for match in re.findall('\d\d\d-\d\d\d-\d\d\d\d', str(html)):
        if match not in visited_match:
            results.append((address, 'PHONE', match))
            visited_match.append(match)

    # Extract email addresses
    for match in re.findall(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b', str(html)):
        # if match not in visited_match:
            results.append((address, 'EMAIL', match))
            # visited_match.append(match)

    # Extract physical addresses
    for match in re.findall(r'\b[A-Za-z\s]+\s*,\s*[A-Za-z]+\s*(?:\.\s*)?\d{5}\b', str(html)):
        if match not in visited_match:
            results.append((address, 'ADDRESS', match))
            visited_match.append(match)

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