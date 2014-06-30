#!/usr/bin/env python
#-*- coding:utf-8 -*-

try:
    import os
    import sys
    reload(sys)
    sys.setdefaultencoding('utf-8')
    import urllib
    import urllib2
    import cookielib
    import base64
    import re
    import hashlib
    import json
    import rsa
    import binascii
    import smtplib
    from email.mime.text import MIMEText
    import time
except ImportError:
        print >> sys.stderr, """\

There was a problem importing one of the Python modules required.
The error leading to this problem was:

%s

Please install a package which provides this module, or
verify that the module is installed correctly.

It's possible that the above module doesn't match the current version of Python,
which is:

%s

""" % (sys.exc_info(), sys.version)
        sys.exit(1)

def get_prelogin_status(username):
    """
    Perform prelogin action, get prelogin status, including servertime, nonce, rsakv, etc.
    """
    #prelogin_url = 'http://login.sina.com.cn/sso/prelogin.php?entry=weibo&callback=sinaSSOController.preloginCallBack&client=ssologin.js(v1.4.5)'
    prelogin_url = 'http://login.sina.com.cn/sso/prelogin.php?entry=weibo&callback=sinaSSOController.preloginCallBack&su=' + get_user(username) + \
     '&rsakt=mod&checkpin=1&client=ssologin.js(v1.4.5)';
    data = urllib2.urlopen(prelogin_url).read()
    p = re.compile('\((.*)\)')
    
    try:
        json_data = p.search(data).group(1)
        data = json.loads(json_data)
        servertime = str(data['servertime'])
        nonce = data['nonce']
        rsakv = data['rsakv']
        return servertime, nonce, rsakv
    except:
        print 'Getting prelogin status met error!'
        return None


def login(username, pwd, cookie_file):
    """"
        Login with username, password and cookies.
        (1) If cookie file exists then try to load cookies;
        (2) If no cookies found then do login
    """
    #If cookie file exists then try to load cookies
    if os.path.exists(cookie_file):
        try:
            cookie_jar  = cookielib.LWPCookieJar(cookie_file)
            cookie_jar.load(ignore_discard=True, ignore_expires=True)
            loaded = 1
        except cookielib.LoadError:
            loaded = 0
            #print 'Loading cookies error'
        
        #install loaded cookies for urllib2
        if loaded:
            cookie_support = urllib2.HTTPCookieProcessor(cookie_jar)
            opener         = urllib2.build_opener(cookie_support, urllib2.HTTPHandler)
            urllib2.install_opener(opener)
            #print 'Loading cookies success'
            return 1
        else:
            return do_login(username, pwd, cookie_file)
    
    else:   #If no cookies found
        return do_login(username, pwd, cookie_file)


def do_login(username,pwd,cookie_file):
    """"
    Perform login action with use name, password and saving cookies.
    @param username: login username
    @param pwd: login password
    @param cookie_file: file name where to save cookies when login succeeded 
    """

    login_data = {
        'entry': 'weibo',
        'gateway': '1',
        'from': '',
        'savestate': '7',
        'userticket': '1',
        'pagerefer':'',
        'vsnf': '1',
        'su': '',
        'service': 'miniblog',
        'servertime': '',
        'nonce': '',
        'pwencode': 'rsa2',
        'rsakv': '',
        'sp': '',
        'encoding': 'UTF-8',
        'prelt': '45',
        'url': 'http://weibo.com/ajaxlogin.php?framelogin=1&callback=parent.sinaSSOController.feedBackUrlCallBack',
        'returntype': 'META'
        }

    cookie_jar2     = cookielib.LWPCookieJar()
    cookie_support2 = urllib2.HTTPCookieProcessor(cookie_jar2)
    opener2         = urllib2.build_opener(cookie_support2, urllib2.HTTPHandler)
    urllib2.install_opener(opener2)
    login_url = 'http://login.sina.com.cn/sso/login.php?client=ssologin.js(v1.4.5)'
    try:
        servertime, nonce, rsakv = get_prelogin_status(username)
    except:
        return
    
    #Fill POST data
    login_data['servertime'] = servertime
    login_data['nonce'] = nonce
    login_data['su'] = get_user(username)
    login_data['sp'] = get_pwd_rsa(pwd, servertime, nonce)
    login_data['rsakv'] = rsakv
    login_data = urllib.urlencode(login_data)
    http_headers = {'User-Agent':'Mozilla/5.0 (X11; Linux i686; rv:8.0) Gecko/20100101 Firefox/8.0'}
    req_login  = urllib2.Request(
        url = login_url,
        data = login_data,
        headers = http_headers
    )
    result = urllib2.urlopen(req_login)
    text = result.read()
    p = re.compile('location\.replace\(\"(.*?)\"\)')
    
    try:
        #Search login redirection URL
        login_url = p.search(text).group(1)
        
        data = urllib2.urlopen(login_url).read()
        
        #Verify login feedback, check whether result is TRUE
        patt_feedback = 'feedBackUrlCallBack\((.*)\)'
        p = re.compile(patt_feedback, re.MULTILINE)
        
        feedback = p.search(data).group(1)
        
        feedback_json = json.loads(feedback)
        if feedback_json['result']:
            cookie_jar2.save(cookie_file,ignore_discard=True, ignore_expires=True)
            after_login = urllib2.urlopen()
            return 1
        else:
            return 0
    except:
        return 0


def get_pwd_wsse(pwd, servertime, nonce):
    """
        Get wsse encrypted password
    """
    pwd1 = hashlib.sha1(pwd).hexdigest()
    pwd2 = hashlib.sha1(pwd1).hexdigest()
    pwd3_ = pwd2 + servertime + nonce
    pwd3 = hashlib.sha1(pwd3_).hexdigest()
    return pwd3

def get_pwd_rsa(pwd, servertime, nonce):
    """
        Get rsa2 encrypted password, using RSA module from https://pypi.python.org/pypi/rsa/3.1.1, documents can be accessed at 
        http://stuvel.eu/files/python-rsa-doc/index.html
    """
    #n, n parameter of RSA public key, which is published by WEIBO.COM
    #hardcoded here but you can also find it from values return from prelogin status above
    weibo_rsa_n = 'EB2A38568661887FA180BDDB5CABD5F21C7BFD59C090CB2D245A87AC253062882729293E5506350508E7F9AA3BB77F4333231490F915F6D63C55FE2F08A49B353F444AD3993CACC02DB784ABBB8E42A9B1BBFFFB38BE18D78E87A0E41B9B8F73A928EE0CCEE1F6739884B9777E4FE9E88A1BBE495927AC4A799B3181D6442443'
    
    #e, exponent parameter of RSA public key, WEIBO uses 0x10001, which is 65537 in Decimal
    weibo_rsa_e = 65537
   
    message = str(servertime) + '\t' + str(nonce) + '\n' + str(pwd)
    
    #construct WEIBO RSA Publickey using n and e above, note that n is a hex string
    key = rsa.PublicKey(int(weibo_rsa_n, 16), weibo_rsa_e)
    
    #get encrypted password
    encropy_pwd = rsa.encrypt(message, key)

    #trun back encrypted password binaries to hex string
    return binascii.b2a_hex(encropy_pwd)


def get_user(username):
    username_ = urllib.quote(username)
    username = base64.encodestring(username_)[:-1]
    return username

last_weibo = ""
last_zan = "赞"
last_zhuanfa = "转发"
last_pinglun = "评论"
last_fabiao = ""

def fenxi(weibo_html):
    """
    分析是否有新的微博、赞、转发、评论
    """
    global last_weibo, last_zan, last_zhuanfa, last_pinglun, last_fabiao
    with open(weibo_html,'r') as f:
        lines = f.readlines()
        l_num = 0 # 微博所在第几行
        for i,l in enumerate(lines):
            if 'WB_detail' in l:
                l_num = i
                break

        line = lines[l_num]

    # 获取最新的微博
    weibo_one_pos = line.find('nick-name')
    weibo_end_pos = line[weibo_one_pos:].find('<\/div>')
    weibo_content = line[weibo_one_pos:weibo_one_pos + weibo_end_pos]
    weibo_start_pos = weibo_content.find('>')
    neirong=weibo_content[weibo_start_pos+3:].strip()
    while True:
        a_start = neirong.find('<a')
        if a_start != -1:
            at_pos = neirong.find('@')
            a_end = neirong.find('<\/a')
            one = neirong[:a_start]
            two = neirong[at_pos:a_end]
            three = neirong[a_end+5:]
            neirong = one+two+three
        else:
            break
    del weibo_content, weibo_start_pos

    start_pos = weibo_one_pos + weibo_end_pos
    end_pos = line[start_pos:].find('举报')
    weibo_from = line[start_pos:start_pos + end_pos]

    # 获取最新的赞
    zan_pos = weibo_from.find('赞')
    zan_start = weibo_from[zan_pos:].find('/em>')
    zan_end = weibo_from[zan_pos+zan_start:].find('<')
    zan_end_end = zan_pos+zan_start+zan_end
    zan = weibo_from[zan_pos+zan_start+4:zan_end_end]
    zan = "赞" + zan

    # 获取微博的转发
    zhuanfa_pos = zan_end_end + weibo_from[zan_end_end:].find('转发')
    zhuanfa_end = zhuanfa_pos + weibo_from[zhuanfa_pos:].find('<')
    zhuanfa = weibo_from[zhuanfa_pos:zhuanfa_end]
    
    # 获取最新的评论
    pinglun_start = zhuanfa_end + weibo_from[zhuanfa_end:].find('评论')
    pinglun_end = pinglun_start + weibo_from[pinglun_start:].find('<')
    pinglun = weibo_from[pinglun_start:pinglun_end]

    # 获取微博的发表时间
    fabiao_start = pinglun_end + weibo_from[pinglun_end:].find('title') + 8
    fabiao_end = fabiao_start + 16
    fabiao = weibo_from[fabiao_start:fabiao_end]

    # 优化性能
    del pinglun_start,pinglun_end,zhuanfa_pos, zhuanfa_end, zan_pos, zan_start, zan_end, zan_end_end

    # 分析微博变动
    if neirong and zan and zhuanfa and pinglun and fabiao:
        if fabiao != last_fabiao:
            fb = True
            last_weibo = neirong
            last_zan = zan
            last_zhuanfa = zhuanfa
            last_pinglun = pinglun
            last_fabiao = fabiao
            return fb,False,False,False
        else:
            fb = False

        if zan != last_zan:
            z = True
            last_zan = zan
        else:
            z = False

        if zhuanfa != last_zhuanfa:
            zf = True
            last_zhuanfa = zhuanfa
        else:
            zf = False

        if pinglun != last_pinglun:
            pl = True
            last_pinglun = pinglun
        else:
            pl = False
    else:
        fb = z = zf = pl = False
    return fb,z,zf,pl


def tixing(fb, z, zf, pl):
    """
    通过邮件发送微博更新提醒
    """
    msg = []
    tail = "%s %s %s %s" %(last_fabiao, last_zan, last_zhuanfa, last_pinglun)
    title = "微博有新动态："

    if fb:
        title = "Ta发表了新的微博"
        z = zf = pl = False
        msg.append(last_weibo)

    if z:
        title += "有人赞 " 
        msg.append(last_zan)
    if zf:
        title += "有人转发 " 
        msg.append(last_zhuanfa)
    if pl:
        title += "有人评论"
        msg.append(last_pinglun)
    i = ""
    for m in msg:
        i += m
    send(title, i, tail)

# 运行前设置邮件发送方和接收方，并将接收方与微信绑定
def send(title, msg, tail):
    send_user = '你的QQ邮箱'
    send_server = "smtp.qq.com"
    user_password = "你的邮箱密码"

    send_to = "接收提醒邮箱地址"

    content = MIMEText(msg+"\r\n"+tail)
    content['Subject'] = title
    content['From'] = '微博提醒<%s>' % send_user
    content['To'] = "%s" % send_to

    smtp = smtplib.SMTP()
    smtp.set_debuglevel(0)
    smtp.connect(send_server)
    smtp.login(send_user, user_password)
    smtp.sendmail(send_user, send_to, content.as_string())
    smtp.quit()
    print "最新微博：".decode('utf-8','ignore').encode('gb2312','ignore')
    print last_weibo.decode('utf-8','ignore').encode('gb2312','ignore')
    print "="*40
    print last_zan.decode('utf-8','ignore').encode('gb2312','ignore')
    print '='*40
    print last_zhuanfa.decode('utf-8','ignore').encode('gb2312','ignore')
    print '='*40
    print last_pinglun.decode('utf-8','ignore').encode('gb2312','ignore')
    print '='*40
    print last_fabiao.decode('utf-8','ignore').encode('gb2312','ignore')
    print '='*40
    print "微博提醒发送成功！".decode('utf-8','ignore').encode('gb2312','ignore')
    return


if __name__ == '__main__':
    username = '微博登录账号'
    pwd = '登录密码'
    cookie_file = 'weibo_login_cookies.dat'

    # 输入你所关注的人的微博UID或Screenname
    user = raw_input("Please input weibo Uid or Screenname:")

    i = 1
    
    while True:
        try:
            if login(username, pwd, cookie_file):
                if i == 1:
                    print 'Login WEIBO succeeded'
                    i += 1
                if user.isdigit():
                    weibo_url = "http://www.weibo.com/u/%s/"
                else:
                    weibo_url = "http://www.weibo.com/%s"
                weibo_page = urllib2.urlopen(weibo_url % user, timeout=10).read()
                with open('weibo.html','w') as f:
                    f.write(weibo_page)
                fabiao_bianhua, zan_bianhua, zhuanfa_bianhua, pinglun_bianhua = fenxi('weibo.html')
                bianhua = [fabiao_bianhua, zan_bianhua, zhuanfa_bianhua, pinglun_bianhua]
                if any(bianhua):
                    #print "%s's weibo has news!" % user
                    tixing(fabiao_bianhua, zan_bianhua, zhuanfa_bianhua, pinglun_bianhua)
                else:
                    pass
            else:
                print 'Login WEIBO failed'
        except Exception,e:
            send("提醒程序出错了",str(e),"已被捕获!")
            print "出错了",e
            raw_input("try again:")
            os.remove('weibo_login_cookies.dat')
            time.sleep(5)
