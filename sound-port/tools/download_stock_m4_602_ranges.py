"""Bounded ranged download of the official public donor; preserves partials."""
import concurrent.futures
import hashlib
import json
from pathlib import Path
import threading
import time
import urllib.request
from download_stock_m4_602 import DIRECTORY,URL,EXPECTED_BYTES


def main():
    DIRECTORY.mkdir(parents=True,exist_ok=True)
    target=DIRECTORY/'BODYDATA.DAT';parts=DIRECTORY/'download-parts';parts.mkdir(exist_ok=True)
    if target.exists():raise FileExistsError('Donor already exists')
    started=time.monotonic();deadline=started+180;chunk=2*1024*1024
    jobs=[(i,a,min(a+chunk,EXPECTED_BYTES))for i,a in enumerate(range(0,EXPECTED_BYTES,chunk))]
    report={'schema':1,'url':URL,'expected_bytes':EXPECTED_BYTES,'parallel_workers':48,
            'chunk_bytes':chunk,'single_stream_partial_preserved':True,'rv_source_modified':False}
    completed=[];errors=[]
    def fetch(job):
        index,start,end=job;destination=parts/f'{index:04d}.bin'
        if destination.exists()and destination.stat().st_size==end-start:return index,end-start
        failure=None
        for attempt in range(2):
            if time.monotonic()>deadline:raise TimeoutError('Three-minute ranged download limit reached')
            temporary=parts/f'{index:04d}.attempt-{attempt}.part'
            try:
                request=urllib.request.Request(URL,headers={'Range':f'bytes={start}-{end-1}',
                    'User-Agent':'Mozilla/5.0','Accept-Encoding':'identity'})
                with urllib.request.urlopen(request,timeout=25)as response,temporary.open('xb')as out:
                    if response.status!=206 or response.headers.get('Content-Range')!=f'bytes {start}-{end-1}/{EXPECTED_BYTES}':
                        raise ValueError('Range response differs from requested donor interval')
                    size=0
                    while size<end-start:
                        if time.monotonic()>deadline:raise TimeoutError('Ranged download deadline')
                        b=response.read(min(256*1024,end-start-size))
                        if not b:break
                        out.write(b);size+=len(b)
                if size!=end-start:raise ValueError('Short range response')
                temporary.rename(destination);return index,size
            except Exception as error:
                failure=error
        raise failure
    with concurrent.futures.ThreadPoolExecutor(max_workers=48)as pool:
        futures={pool.submit(fetch,j):j[0]for j in jobs}
        for f in concurrent.futures.as_completed(futures):
            try:
                completed.append(f.result())
                if len(completed)%16==0:print(json.dumps({'ranges':len(completed),'total_ranges':len(jobs),
                    'bytes':sum(n for _,n in completed),'seconds':round(time.monotonic()-started,1)}),flush=True)
            except Exception as error:errors.append({'index':futures[f],'error':f'{type(error).__name__}: {error}'})
    if errors:
        report.update(status='RANGED_DOWNLOAD_INCOMPLETE',completed_ranges=len(completed),
                      downloaded_bytes=sum(n for _,n in completed),errors=errors)
    else:
        temporary=DIRECTORY/'BODYDATA.parallel.part';digest=hashlib.sha256();size=0
        with temporary.open('xb')as out:
            for index,_,_ in jobs:
                with (parts/f'{index:04d}.bin').open('rb')as source:
                    while True:
                        b=source.read(1024*1024)
                        if not b:break
                        out.write(b);digest.update(b);size+=len(b)
        if size!=EXPECTED_BYTES:raise ValueError('Merged donor size mismatch')
        with temporary.open('rb')as f:
            if f.read(8)!=b'\x89UFU\r\n\x1a\n':raise ValueError('Wrong DAT magic')
        temporary.rename(target)
        report.update(status='DOWNLOADED',bytes=size,sha256=digest.hexdigest(),path=str(target))
    report['seconds']=round(time.monotonic()-started,2)
    (DIRECTORY/'download-parallel-manifest.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf8')
    print(json.dumps({k:v for k,v in report.items()if k!='errors'},ensure_ascii=False),flush=True)
    if errors:raise SystemExit(1)


if __name__=='__main__':main()
