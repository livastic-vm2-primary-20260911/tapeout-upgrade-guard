#!/usr/bin/env python3
"""Rebuild silent demo slides from an actual Chrome screenshot and verifiable evidence.
Needs Pillow, FFmpeg separately. Video claims no funding, security audit or buyers.
"""
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont, ImageOps
import json
import textwrap
import os

BASE=Path(__file__).resolve().parents[1]
OUT=BASE/'media/frames'
OUT.mkdir(parents=True,exist_ok=True)
snap=json.load(open(BASE/'evidence/20261023_xlayer_mainnet_pinned.json'))
older=json.load(open(BASE/'evidence/20261023_xlayer_block_73981688.json'))
diff=json.load(open(BASE/'evidence/comparison_73981688_to_73981911.json'))
assert snap['network']['chain_id']==196
assert diff['status']=='NO_OBSERVED_DIFFERENCE'
DOC=snap['source']['external_documented_factory_implementation']
LIVE=snap['components']['factory']['implementation']['address']
assert DOC!=LIVE
BG='#09111b';FG='#eaf5ff';MUTED='#a8bad0';GREEN='#73e6c4';WARN='#ffca83';LINE='#2a4256'
W,H=1280,720
FONT='/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf'
BOLD='/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf'
def font(sz,bold=False):
    return ImageFont.truetype(BOLD if bold else FONT,sz)
def base(number,eyebrow):
    im=Image.new('RGB',(W,H),BG);d=ImageDraw.Draw(im)
    d.rectangle((0,0,W,7),fill=GREEN)
    d.text((55,34),'T✦  TAPEOUT UPGRADE GUARD',font=font(20,True),fill=GREEN)
    d.text((W-55,38),'X LAYER · CHAIN 196',font=font(15),fill=MUTED,anchor='ra')
    d.line((55,89,W-55,89),fill=LINE,width=2)
    d.text((55,H-42),eyebrow.upper(),font=font(14,True),fill=GREEN)
    d.text((W-55,H-42),str(number)+' / 7',font=font(15),fill=MUTED,anchor='ra')
    return im,d
def multiline(draw,text,xy,sz=26,color=FG,spacing=12,width=65,bold=False):
    y=xy[1]; x=xy[0]
    for line in textwrap.wrap(text,width) if isinstance(text,str) else text:
        draw.text((x,y),line,font=font(sz,bold),fill=color)
        y+=sz+spacing
    return y
def add_slide(n,im):
    p=OUT/('slide_%02d.png'%n); im.save(p,optimize=True)
    return p
im,d=base(1,'independent public developer prototype')
d.text((62,198),'Know what changed',font=font(55,True),fill=FG)
d.text((62,272),'before you trust the upgrade.',font=font(42,True),fill=GREEN)
multiline(d,'TapeOut factory + beacon implementation checks at pinned blocks on X Layer.',(64,383),24,MUTED,width=62)
d.rounded_rectangle((62,533,592,593),radius=12,fill='#113e3b',outline='#3b8479',width=2)
d.text((88,553),'NO WALLET · NO GAS · NO SIGNATURE',font=font(17,True),fill=GREEN)
add_slide(1,im)

screenshot=Image.open(BASE/'media/live_dashboard_20261023.png').convert('RGB')
im,d=base(2,'live public website · actual screenshot')
crop=ImageOps.contain(screenshot,(1170,548),Image.Resampling.LANCZOS)
x=(W-crop.width)//2; y=111
im.paste(crop,(x,y))
d.rectangle((x,y,x+crop.width-1,y+crop.height-1),outline='#59758a',width=3)
d.rounded_rectangle((90,590,1190,638),radius=8,fill='#102936')
d.text((107,604),'Live page: factory / beacon evidence fetched from checked-in X Layer JSON',font=font(16),fill=GREEN)
add_slide(2,im)

full=Image.open(BASE/'media/live_full_20261023.png').convert('RGB')
crop=full.crop((0,730,1440,1690))
zoom=ImageOps.contain(crop,(1150,540),Image.Resampling.LANCZOS)
im,d=base(3,'real deployed addresses and sha-256 fingerprints')
im.paste(zoom,((W-zoom.width)//2,105))
d.rectangle(((W-zoom.width)//2,105,(W+zoom.width)//2,105+zoom.height),outline='#5c7886',width=3)
d.text((88,655),'Factory proxy · implementation bytecode · two TapeOut beacons',font=font(17,True),fill=GREEN)
add_slide(3,im)

im,d=base(4,'concrete source-reference difference — not an exploit')
d.text((65,156),'Documented implementation',font=font(30,True),fill=MUTED)
d.rounded_rectangle((60,213,1220,298),radius=13,fill='#172736')
d.text((85,240),DOC,font=font(25),fill=FG)
d.text((65,345),'Live onchain EIP-1967 implementation',font=font(30,True),fill=GREEN)
d.rounded_rectangle((60,402,1220,487),radius=13,fill='#163a3b',outline='#397f75')
d.text((85,430),LIVE,font=font(25,True),fill=GREEN)
multiline(d,'Difference may mean a stale third-party reference or an upgrade. No malicious behavior is established.',(66,545),20,WARN,width=88)
add_slide(4,im)

im,d=base(5,'reproduce from source at real pinned blocks')
d.text((65,150),'Two independently pinned blocks',font=font(34,True),fill=FG)
d.text((70,224),str(older['network']['block_number'])+'  →  '+str(snap['network']['block_number']),font=font(51,True),fill=GREEN)
d.rounded_rectangle((62,309,1215,407),radius=10,fill='#122432',outline='#354e66')
d.text((83,334),'NO_OBSERVED_DIFFERENCE',font=font(30,True),fill=GREEN)
d.text((82,380),'in sampled code, implementation pointers and owner observations',font=font(14),fill=MUTED)
d.text((67,467),'python3 -B tapeout_guard.py snapshot --block 73981688 --out old.json',font=font(17),fill=FG)
d.text((67,506),'python3 -B tapeout_guard.py diff old.json latest.json',font=font(17),fill=FG)
d.text((67,576),'Offline tests: 29 / 29 PASS',font=font(24,True),fill=GREEN)
add_slide(5,im)

im,d=base(6,'real user problem and monetization hypothesis')
d.text((64,151),'For developers, integrators & risk teams',font=font(36,True),fill=FG)
multiline(d,['1. Pin onchain implementation evidence before a release.',
             '2. Compare code and control drift against a prior snapshot.',
             '3. Send a reproducible exception bundle for human review.'],(70,242),25,MUTED,spacing=19)
d.rounded_rectangle((63,460,1218,558),radius=12,fill='#14332f')
multiline(d,'Possible paid release-review pilot: 9–19 USDC, only after a real buyer agrees. Paying customers so far: 0.',(88,479),20,GREEN,width=85)
add_slide(6,im)

im,d=base(7,'free open source and evidence')
d.text((67,144),'Try the live tool',font=font(46,True),fill=FG)
multiline(d,'livastic-vm2-primary-20260911.github.io/tapeout-upgrade-guard/',(70,244),23,GREEN,width=70)
d.text((70,349),'Review the full source + 29 passing tests',font=font(25,True),fill=MUTED)
multiline(d,'github.com/livastic-vm2-primary-20260911/tapeout-upgrade-guard',(70,396),22,FG,width=74)
d.rounded_rectangle((67,512,1217,593),radius=9,fill='#1a2836')
d.text((86,536),'No security guarantees. No sale or prize is claimed.',font=font(20,True),fill=WARN)
add_slide(7,im)
print('GENERATED_SLIDES',len(list(OUT.glob('slide_*.png'))))
