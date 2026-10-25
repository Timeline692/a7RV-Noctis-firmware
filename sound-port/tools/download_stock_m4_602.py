"""Download the official public M4 donor to its own reference directory."""
import hashlib
import json
from pathlib import Path
import time
import urllib.request

ROOT=Path(__file__).resolve().parents[2]
DIRECTORY=ROOT/'references/stock-a7m4-602'
URL='https://support.d-imaging.sony.co.jp/download/NEX/YE19b5b7b3/BODYDATA.DAT?fm=cn'
EXPECTED_BYTES=757480856


def main():
    DIRECTORY.mkdir(parents=True,exist_ok=True)
    target=DIRECTORY/'BODYDATA.DAT';partial=DIRECTORY/'BODYDATA.DAT.part'
    if target.exists() or partial.exists():raise FileExistsError('Existing donor or partial file will not be overwritten')
    started=time.monotonic();digest=hashlib.sha256();total=0;last=0
    report={'schema':1,'source_page':'https://service.sony.com.cn/download/firm/00003010.html',
            'url':URL,'expected_bytes':EXPECTED_BYTES,'path':str(target.relative_to(ROOT)),
            'rv_source_modified':False}
    try:
        request=urllib.request.Request(URL,headers={'User-Agent':'Mozilla/5.0','Accept-Encoding':'identity'})
        with urllib.request.urlopen(request,timeout=40)as response,partial.open('xb')as output:
            report['http_status']=response.status;report['content_length']=response.headers.get('Content-Length')
            report['resolved_url']=response.url
            print(json.dumps({'download':'started','status':response.status,'content_length':report['content_length']}),flush=True)
            while True:
                if time.monotonic()-started>300:raise TimeoutError('Five-minute donor download limit reached')
                block=response.read(4*1024*1024)
                if not block:break
                output.write(block);digest.update(block);total+=len(block)
                if total-last>=32*1024*1024:
                    print(json.dumps({'bytes':total,'percent':round(total/EXPECTED_BYTES*100,1),'seconds':round(time.monotonic()-started,1)}),flush=True);last=total
        if total!=EXPECTED_BYTES:raise ValueError(f'Donor size {total} differs from official {EXPECTED_BYTES}')
        with partial.open('rb')as f:
            if f.read(8)!=b'\x89UFU\r\n\x1a\n':raise ValueError('Not a Sony DAT header')
        partial.rename(target)
        report.update(status='DOWNLOADED',bytes=total,sha256=digest.hexdigest(),seconds=round(time.monotonic()-started,2))
    except Exception as error:
        report.update(status='DOWNLOAD_FAILED',bytes=total,partial_path=str(partial.relative_to(ROOT)),
                      partial_sha256=digest.hexdigest(),seconds=round(time.monotonic()-started,2),error=f'{type(error).__name__}: {error}')
    (DIRECTORY/'download-manifest.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf8')
    print(json.dumps(report,ensure_ascii=False),flush=True)
    if report['status']!='DOWNLOADED':raise SystemExit(1)


if __name__=='__main__':main()
