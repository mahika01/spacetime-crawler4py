import re
from urllib.parse import urlparse
from bs4 import BeautifulSoup #Handles HTML pages 
from lxml import html #Makes links absolute 
import urllib.request
import ssl

from threading import RLock

local_lock = RLock() #general thread lock for data structures 
robot_sitemap_lock = RLock() #lock for robots/sitemaps data structures
simhash_lock = RLock() #lock for simhash


num_unique_links = 0 
unique_urls = set() #set of unique urls
longest_page = [0, None] #stores longest page info [length of page, url]
all_words = {} #dict of all words and frequencies 
ics_subdomains = {} #dict of ics subdomains and # unique page
urls_seen = [] #all URLs encountered
robots_is_allowed = {} #URLs allowed/disallowed by robots.txt files
sitemaps = {} #dict of URLs mapped to a list of URL's sitemaps 
simhash_fingerprints = {} #fingerprint
#words to ignore in all_words
stop_words = ['a', 'about', 'above', 'after', 'again', 'against', 'all', 'am',
    'an', 'and', 'any', 'are', "aren't", 'as', 'at', 'be', 'because', 'been',
    'before', 'being', 'below', 'between', 'both', 'but', 'by', "can't",
   'cannot', 'could', "couldn't", 'did', "didn't", 'do', 'does', "doesn't",
    'doing', "don't", 'down', 'during', 'each', 'few', 'for', 'from', 'further', 
    'had', "hadn't", 'has', "hasn't", 'have', "haven't", 'having', 'he', "he'd", 
    "he'll", "he's", 'her', 'here', "here's", 'hers', 'herself', 'him', 'himself', 
    'his', 'how', "how's", 'i', "i'd", "i'll", "i'm", "i've", 'if', 'in', 'into',
    'is', "isn't", 'it', "it's", 'its', 'itself', "let's", 'me', 'more', 'most', 
    "mustn't", 'my', 'myself', 'no', 'nor', 'not', 'of', 'off', 'on', 'once', 'only',
    'or', 'other', 'ought', 'our', 'ours', 'ourselves', 'out', 'over', 'own', 'same',
    "shan't", 'she', "she'd", "she'll", "she's", 'should', "shouldn't", 'so', 'some',
    'such', 'than', 'that', "that's", 'the', 'their', 'theirs', 'them', 'themselves', 
    'then', 'there', "there's", 'these', 'they', "they'd", "they'll", "they're", 
    "they've", 'this', 'those', 'through', 'to', 'too', 'under', 'until', 'up', 
    'very', 'was', "wasn't", 'we', "we'd", "we'll", "we're", "we've", 'were',
    "weren't", 'what', "what's", 'when', "when's", 'where', "where's", 
    'which', 'while', 'who', "who's", 'whom', 'why', "why's", 'with', "won't",
    'would', "wouldn't", 'you', "you'd", "you'll", "you're", "you've", 'your',
    'yours', 'yourself', 'yourselves']

def scraper(url, resp):
    '''
    Scrapes the page referred to by url 
    Retrieve required information and get list of urls to scrape further
    Return valid links
    '''
    
    links = extract_next_links(url, resp)
    valid_links = []
    for link in links:
        if is_valid(link):
            valid_links.append(link)
    with open("added_to_frontier.txt", "a") as file:
                file.write(str(valid_links) + "\n\n\n\n")

    #return [link for link in links if is_valid(link)]
    return valid_links

def extract_next_links(url, resp):
    '''
      url: the URL that was used to get the page
      resp.url: the actual url of the page
      resp.status: the status code returned by the server. 200 is OK, you got the page. Other numbers mean that there was some kind of problem.
      resp.error: when status is not 200, you can check the error here, if needed.
      resp.raw_response: this is where the page actually is. More specifically, the raw_response has two parts:
              resp.raw_response.url: the url, again
              resp.raw_response.content: the content of the page!
      Return a list with the hyperlinks (as strings) scrapped from resp.raw_response.content
    '''
    sub_urls = set() # Set of URL (unique) in this page to return 
    empty_set = set()
    if resp.status == 200: 
        if not keep_unique(resp.url):
            # This URL is already handled
            return empty_set
        

        #if not url in urls_visited:
        #urls_visited.append(url)
        # Check if this URL is already handled
        #check if url is a subdomain of ics.uci.edu and
        #update count of subdomains
        check_save_ics_subdomain(resp.url) 

        #check quality
        #make sure specific content not crawled
        #calendars, events, datasets, etc. 
        if not check_qual(url):
            return empty_set
        
        #parse robots file
        parse_robots(url)

        #parse sitemaps
        #add urls found on sitemaps to returned set  
        urls = parse_sitemaps(url)
        if len(urls) > 0: 
            for url in urls: 
                url_defrag = urllib.parse.urldefrag(url).url
                sub_urls.union(set(url_defrag))        

        try:
            content = html.fromstring(resp.raw_response.content) # Get the web page contents
            content.make_links_absolute(url)# Make all urls in this page absolute
            soup = BeautifulSoup(html.tostring(content), 'html.parser' ) # Parse html
            word_count, weights = get_words(url, soup) 
            
            if word_count < 128: #too little info 
                return empty_set #not worth crawling
            
            if not simhash_check(url, weights):
                return empty_set
            
            for a_tag in soup.findAll('a', href=True): # Traverse links in the page
                #print("URL {}, {}".format(url, soup))
                href=a_tag['href']
                href = urllib.parse.urldefrag(href).url # Defrag to avoid same link
                with local_lock:
                    if not href in urls_seen:
                        urls_seen.append(href)
                        sub_urls.add(href)
        except:
            print("EXCEPTION in extract_next_links")
            return empty_set
            pass
    return list(sub_urls)

def is_valid(url):
    '''
      Decide whether to crawl this url or not. 
      If you decide to crawl it, return True; otherwise return False.
      There are already some conditions that return False.
    '''
    try:
        parsed = urlparse(url)
        if parsed.scheme not in set(["http", "https"]):
            #print("NOT VALID: parsed.scheme")
            return False

        allowed_domains = ['.*\.ics\.uci\.edu/.*', '.*\.cs\.uci\.edu/.*', 
        '.*\.informatics\.uci\.edu/.*', '.*\.stat\.uci\.edu/.*',
        'today\.uci\.edu/department/information_computer_sciences/.*']
        
        valid = False
        # Follow links if the domain is inour allowed list
        for domain in allowed_domains:
            if re.match(parsed.scheme+"://"+domain, url):
                valid = True
                break
        if not valid:
            return valid
        
        #Check robots.txt
        #check if robots.txt allows url to be crawled
        if not robots_is_url_allowed(url):
            return False
        
        #Check repeating path segments
        #URLs with too many repeating path segments
        #Are likely to be traps/not worth crawling         
        if not check_no_repeat(parsed):
            return False
    
        #check length of URL
        #if URL too big == potential trap
        if len(url) > 128:
            return False 
            
        #avoid specific traps
        if url.count("swiki.ics.uci.edu/") > 0:
            return False
        
        if url.count("wiki.ics.uci.edu/") > 0:
            return False
        
        if url.count("evoke.ics.uci.edu/") > 0:
            return False   
        
        if re.match(".*\?filter.*", url):
            return False
        
        if re.match(".*\?.*=diff.*", url):
            return False
                
        #modified regex by taking out $ from end ?
        return not re.match(
            r".*\.(css|js|bmp|gif|jpe?g|ico"
            + r"|png|tiff?|mid|mp2|mp3|mp4"
            + r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
            + r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names"
            + r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
            + r"|epub|dll|cnf|tgz|sha1"
            + r"|thmx|mso|arff|rtf|jar|csv"
            + r"|rm|smil|wmv|swf|wma|zip|rar|gz)", parsed.path.lower())
    except TypeError:
        print ("TypeError for ", parsed)
        raise

def get_robots_content(url):
    '''
    get contents of robots.txt 
    Return contents and parsed URL
    '''
    parsed = urlparse(url)
    robot_url = parsed.scheme + "://" + parsed.netloc +  '/robots.txt'
    text = None

    try:
        context = ssl._create_unverified_context() #disable site verification
        #check that page exists
        robots = urllib.request.urlopen(robot_url, context = context) 
        robots_bytes = robots.read()
        text = robots_bytes.decode("utf8") 
    except:
        pass
    return text, parsed

def parse_robots(url):
    '''
    Thread lock
    Parse through robots.txt
    Determined what is allowed/disallowed, add to dict
    Add sitemaps to sitemaps dict
    Write robots content to file
    '''
    local_robots_is_allowed = {} 
    robots_txt_contents, parsed = get_robots_content(url)
    try:
        with robot_sitemap_lock:
            if robots_txt_contents:
                if parsed.netloc in robots_is_allowed:
                    return
                robots_lines = robots_txt_contents.split("\n")
                i = 0
                is_agent_info = False
                while i < len(robots_lines):
                    line_split = robots_lines[i].split()
                    if robots_lines[i].lower().startswith("user-agent"):
                        if robots_lines[i].count("*") > 0:
                            is_agent_info = True
                        else:
                            is_agent_info = False
                    elif is_agent_info:
                        if robots_lines[i].count("Disallow") > 0:
                            local_robots_is_allowed[line_split[1]] = False
                        if robots_lines[i].count("Allow") > 0:
                            local_robots_is_allowed[line_split[1]] = True
                    if robots_lines[i].count("Sitemap") > 0:
                        if parsed.netloc in sitemaps:
                            sitemaps[parsed.netloc].append(line_split[1])
                        else:
                            sitemaps[parsed.netloc] = [line_split[1]]
                    i += 1 
            robots_is_allowed[parsed.netloc] = local_robots_is_allowed
            with open("robots_info.txt", "w") as file:
                file.write(str(robots_is_allowed) + "\n\n\n\n")
    except:
        pass
    

def robots_is_url_allowed(url):
    '''
    Thread lock
    Check if url is explicitly allowed or disallowed by robots.txt
    If not explicitly allowed/disallowed, return True
    Write to file
    '''
    Return True if URL 
    parsed = urlparse(url)
    allowed = None
    with robot_sitemap_lock:
        if parsed.netloc in robots_is_allowed: 
            for k,v in robots_is_allowed[parsed.netloc].items():
                if re.search(k, url):
                    #implementing the least restrictive approach for multiple matches
                    if allowed != None and allowed != v:
                        allowed = True
                    if allowed == None:
                        allowed = v
        if allowed == None:
            allowed = True
        with open("robots_allowed.txt", "a") as file:
                file.write("Is {} allowed? {}\n\n\n\n".format(url, allowed))
        return allowed

def parse_sitemaps(url):
    '''
    Thread lock
    Parse through sitemaps, find URLs to parse or additional 
    Sitemaps to parse through 
    Return URLs found
    '''
    with robot_sitemap_lock:
        parsed = urlparse(url)
        urls_sitemaps = []
        if parsed.netloc not in sitemaps:
            return urls_sitemaps 
        sitemaps_save = sitemaps[parsed.netloc]
        try:
            while len(sitemaps[parsed.netloc]) > 0:
                sitemap_url = sitemaps[parsed.netloc].pop()
                context = ssl._create_unverified_context()
                sites = urllib.request.urlopen(sitemap_url, context = context)
                sites_bytes = sites.read()
                sites_text = sites_bytes.decode("utf8")
                soup = BeautifulSoup(sites_text,features="xml")
                urls = soup.find_all("loc")
                for url in urls:
                    urls_sitemaps.append(url.text)
                    if re.match(".*.xml.*", url.text):
                        sitemaps[parsed.netloc].append(url.text)
                        sitemaps_save.append(url.text)
                    else:
                        urls_sitemaps.append(url.text)
            sitemaps[parsed.netloc] = sitemaps_save
        except:
            pass
        sitemaps[parsed.netloc] = []
        with open("sitemaps.txt", "w") as file:
            file.write(str(sitemaps))
        with open("urls_from_sitemaps.txt", "a") as file:
            file.write("{} {}".format(url, str(urls_sitemaps)))
        return urls_sitemaps

def keep_unique(url) -> bool:
    '''
    Thread lock
    Add URL to unique_urls if it does not exist in set
    Return True if url is added to set
    '''
    with local_lock:
        if url in unique_urls:
            return False
        unique_urls.add(url)
        global num_unique_links
        num_unique_links += 1
        _save_unique_urls(num_unique_links, url)
        return True  
                            
def get_words(url, soup) -> int:
    '''
    Thread lock
    Counts number of words 
    Updates longest page
    Return word count
    '''
    with local_lock:
        text = soup.get_text() 
        count = 0
        page_word_freq = {}
        for line in text.splitlines():
            for token in re.split(r"!| |\?|,|\.", line):
                token_lower = token.lower()
                match = re.match("([a-z][a-z']+)", token_lower)
                if match:
                    word=match[0]
                    if word not in stop_words:
                        if word in all_words:
                            all_words[word] += 1
                        else:
                            all_words[word] = 1
                        if word in page_word_freq:
                            page_word_freq[word] += 1
                        else:
                            page_word_freq[word] = 1
                        count += 1
        #update longest page info here + save to file
        if count > longest_page[0]:
            longest_page[0] = count
            longest_page[1] = url
            _save_longest_page()
        _save_fifty_words(fifty_most_common())
        return count, page_word_freq

def simhash_check(url, weights):
    '''
    Thread lock 
    Find fingerprint of page
    Determine whether page is similar to previously crawled pages
    Return True if page is different from previously crawled pages
    '''
    different_enough = True
    NUM_BITS = 16
    vector = [0]*NUM_BITS
    for word in weights:
        whash = hash(word)
        for b in range(NUM_BITS):
            mask = 1 << b
            bit_ = whash & mask
            # 0b01100001 & 0b01000000
            if bit_ > 0:
                vector[b] += weights[word]
            else:
                vector[b] -= weights[word]
    fingerprint = 0
    for b in range(NUM_BITS):
        if vector[b] > 0:
            fingerprint = fingerprint | 1<<b
    with simhash_lock:
        for other_url, other_fingerprint in simhash_fingerprints.items():
            num_same = 0
            for b in range(NUM_BITS):
                mask=1<<b
                if fingerprint&mask == other_fingerprint&mask:
                    num_same += 1
            sim_factor = num_same/NUM_BITS
            if sim_factor > 0.95: #threshold 
                print("SIMHASH CHECK! {} and {} are similar.".format(url, other_url))
                different_enough = False
                break
        simhash_fingerprints[url] = fingerprint
        _save_simhash_fingerprints()
    return different_enough

def check_no_repeat(parsed) -> bool:
    '''
    Check to make sure path does not have
    Many repeating path segments
    Store path segments in dictionary and check frequency
    Return False if path segment repeats 2 or more times
    '''
    path_segments = {}
    for p in parsed.path.split("/"):
        if p in path_segments and p:
            path_segments[p] += 1
            if path_segments[p] >= 2: 
                return False
        else:  
            path_segments[p] = 1
    return True
    

def fifty_most_common() -> list: 
    '''
    Thread lock
    Return fifty most frequent words and frequencies 
    Sorted by highest to lowest frequency
    Format: [(word1, frequency), (word2, frequency).. (word50, frequency)]
    Return: list of 50 most common words
    '''
    with local_lock: 
        fifty_freq = sorted(all_words.items(), key=lambda word: word[1],
                        reverse=True)
        return fifty_freq[:50]

def check_qual(url) -> bool:
    '''
    Check to make sure URL is not for
    Calendar, events, archive, datasets
    Filters out traps + large unneeded content
    Return: False if url matches regex filter
    ''' 
    #trap, dynamic links; returns false if match
    return not re.match(".*/(calendar|events|archive|datasets).*", url)

def check_save_ics_subdomain(url):
    '''
    Check if URL is a subdomain of ics.uci.edu
    Use Regex
    Store to global dict save_ics_subdomains
    '''

    parsed = urlparse(url)
    domain = '.*\.ics\.uci\.edu'
    if re.match(domain, parsed.netloc):
        subdomain = parsed.scheme + "://" + parsed.netloc
        with local_lock:
            if subdomain in ics_subdomains:
                ics_subdomains[subdomain] += 1
            else:
                ics_subdomains[subdomain] = 1
            _save_ics_subdomains()

def _save_unique_urls(num_links, url):
    '''
    Append Unique URLS to file
    Called in keep_unique
    '''
    with open("unique_urls.txt", "a") as file:
        file.write(str(num_links) + " " + url + "\n")

def _save_longest_page():
    '''
    Append longest page to file
    Called in get_words
    '''
    with open("longest_page.txt", "a") as file:
        file.write(str(longest_page[0]) + " " + str(longest_page[1]) + "\n")

def _save_ics_subdomains():
    '''
    Thread lock in calling function
    No locking in this function
    Append ics_subdomains to file
    Called in check_save_ics_subdomains
    '''
    sorted_subdomains = [(subdomain, freq) for subdomain,
     freq in sorted(ics_subdomains.items())]
    with open("ics_subdomains.txt", "a") as file:
        file.write(str(sorted_subdomains) + "\n\n\n\n")

def _save_fifty_words(fifty_words):
    '''
    Append top fifty words across all URLs to file
    Called in get_words
    '''
    with open("fifty_words.txt", "w") as file:
        file.write(str(fifty_words) + "\n\n\n\n")

def _save_simhash_fingerprints():
    with open("simhash_fingerprints.txt", "w") as file:
        file.write(str(simhash_fingerprints) + "\n\n\n\n")
