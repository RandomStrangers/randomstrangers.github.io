import bottle, threading, json, urllib, subprocess, pygeoip, imghdr, os, bcrypt, requests  # holy fucking shit
import time, psutil, datetime  # why would i need to fucking do this
from hashlib import md5, sha256
from random import randint

app = bottle.Bottle()
gi = pygeoip.GeoIP('GeoIP.dat')

config_file = open('config.json', 'r')
config = json.loads(config_file.read())

if not os.path.exists('skins/'):
    os.mkdir('skins/')
if not os.path.exists('skins/tmp/'):
    os.mkdir('skins/tmp/')

header = f'''
<head>
    <link href="https://fonts.googleapis.com/css?family=Source+Sans+Pro:400,700,300" rel="stylesheet" type="text/css">
    <link href="asset/css/reset.css" rel="stylesheet" type="text/css">
    <link href="asset/css/style.css" rel="stylesheet" type="text/css">
    <link href="asset/css/form.css" rel="stylesheet" type="text/css">
    <link href="asset/css/pygments.css" rel="stylesheet" type="text/css">
</head>
    <div id="footsticker">
        <div id="navbar">
            <div class="container">
                <a id="nav_title" href="/"><h1>{config['instance']}</h1></a>
                <ul id="nav_links">
                    ADMINPANELHEREaa
                    <li>
                        <a href='/servers'>Servers</a>
                    </li>
                    PQOYIEBUTTONSHERE
                </ul>
            </div>
        </div>
        <div id="content">
            <div class="container">
'''
endder = '''
            </div>
        </div>
        <div id="footer">
            <div class="container">
                <small>ClassiCube and it's designs are owned by the ClassiCube team. I am not affiliated with ClassiCube. Dev: IHateFileManagers</small>
            </div>
        </div>
    </div>
'''
def uptime():
    uptime_secs = time.time() - psutil.boot_time()
    delta = datetime.timedelta(seconds=uptime_secs)
    days = delta.days
    seconds = int(delta.seconds)
    hours, seconds = divmod(seconds, 3600)
    minutes, seconds = divmod(seconds, 60)
    return f'{days} days, {hours} hours, {minutes} minutes, {seconds} seconds'

def finduser(user):
    users_read = open('users.json', 'r')
    try:
        users = json.loads(users_read.read())
    except json.decoder.JSONDecodeError:
        return {'user': '', 'password': '', 'admin': False}
    users_read.close()
    for i in users:
        if i['user'].lower() == user.lower():
            return i
    return {'user': '', 'password': '', 'admin': False, 'banned': False, 'ban_reason': ''}

def getusers():
    users_read = open('users.json', 'r')
    try:
        users = json.loads(users_read.read())
    except json.decoder.JSONDecodeError:
        return {'user': '', 'password': '', 'admin': False}
    users_read.close()
    return users

def getadminamount():
    users_read = open('users.json', 'r')
    b = 0
    try:
        users = json.loads(users_read.read())
    except json.decoder.JSONDecodeError:
        return {'user': '', 'password': '', 'admin': False}
    users_read.close()
    for i in users:
        if i['admin']:
            b += 1
    return b

global servers
#servers = {'asd': {"country_abbr":"PL","featured":False,"salt":"6a44da34c560566b5b0e264bac2ec8e9","max":256,"name":"nuts & berries [gay freebuild]","players":0,"software":"MCGalaxy 1.9.5.3","uptime":793312,"web":True,"ip":"87.205.7.82","port":'25565','hash':'6a44da34c560566b5b0e264bac2ec8e9', 'public': True}}
servers = {}
@app.route('/')
def hello():
    try:
        cook = urllib.parse.unquote(bottle.request.get_cookie("login"))
    except:
        cook = '["khldgfjhagfajgfhakgfjadhgladkgjhadgfkladjgfh", "2"]'
    cook = json.loads(cook)
    user = finduser(cook[0])
    if user['banned']:
        bottle.redirect('/moderation')
    if user['admin']:
        adpanelentry = '<li><a href="/apanel">Admin Panel</a></li>'
    else:
        adpanelentry = ''
    return ((header.replace('PQOYIEBUTTONSHERE', '<li><a href="/login">Log in</a></li><li><a class="button" href="/signup">Sign up</a></li>') if not login(cook[0], cook[1]) else header.replace('PQOYIEBUTTONSHERE', f'<li><a href="/gtfo">Log out</a></li><li><a class="button" href="user">{cook[0]}</a></li>').replace('ADMINPANELHEREaa', adpanelentry)).replace('ADMINPANELHEREaa', adpanelentry) +
            f"<h3>Welcome to VoidCute - version 3</h3>{config['instdesc']}"
            f"<p>Contact the server admin ({config['webmaster']}) through their email address <code>{config['instadminmail']}</code> if you need help with anything.</p>"
            f"<p><a href=\"https://git.gay/intensivecareunitep/classicute\">VoidCute project link</a></p>"
            f"<h1>Instance statistics</h1>"
            f"<p>The server has been up for {uptime()}.</p>"
            f"<p>There are currently {len(getusers())} users registered ({getadminamount()} of which are administrators).</p>"
            f"<p>There are currently {len(servers)} servers online and sending heartbeats to {config['instance']}.</p>"
            f"<h1>Client downloads</h1>"
            f"<p><a href=\"/asset/clients/VCWIN.EXE\">Client for Windows</a><br>"
            f"<a href=\"/asset/clients/VCUNIX\">Client for Linux</a></p>"
            f"<p>...but if you don't trust me enough, you can always <a href=\"/play\">play on the web client.</a></p>"
            + endder)

@app.route('/moderation')
def banished():
    try:
        cook = urllib.parse.unquote(bottle.request.get_cookie("login"))
    except:
        cook = '["khldgfjhagfajgfhakgfjadhgladkgjhadgfkladjgfh", "2"]'
    cook = json.loads(cook)
    user = finduser(cook[0])
    if user['admin']:
        adpanelentry = '<li><a href="/apanel">Admin Panel</a></li>'
    else:
        adpanelentry = ''
    return ((header.replace('PQOYIEBUTTONSHERE', '') if not login(cook[0], cook[1]) else header.replace('PQOYIEBUTTONSHERE', f'')) +
            f"<h1>Termination notice</h1>"
            f"<p>Your account was found to be in violation of the instance's rules, and as such we decided to terminate your account.</p>"
            f"<h3>Why you were terminated:</h3>"
            f"<p>{user['ban_reason']}</p>"
            f"<p><a href=\"/gtfo\">Click here to log out.</a></p>"
            + endder).replace("<a href='/servers'>Servers</a>", "").replace('ADMINPANELHEREaa', f'')

@app.route('/asset/<path:path>')
def getasset(path):
    if "../" in path:
        return "WHAT THE FUCK ARE YOU DOING???"
    return bottle.static_file(path, root='assets/')

@app.route('/static/<path:path>')
def getasset(path):
    if "../" in path:
        return "WHAT THE FUCK ARE YOU DOING???"
    return bottle.static_file(path, root='web/static')

@app.route('/skin/<path:path>')
def getasset(path):
    if "../" in path:
        return "WHAT THE FUCK ARE YOU DOING???"
    return bottle.static_file(f'{path}', root='skins/')

@app.route('/favicon.ico')
def favicon():
    try:
        filet = open(f'assets/favicon.ico', 'rb')
    except FileNotFoundError:
        bottle.abort(404, "Could not find asset")
    return filet.read()
    #return bottle.static_file(f'{path}')

@app.route('/login', method='POST')
def log():
    loggedin  = False
    bodytext  = bottle.request.forms
    name      = bodytext.user
    password  = bodytext.pw
    pwencoded = sha256(password.encode('utf-8')).hexdigest()
    users     = open('users.json', 'r')
    userslist = json.loads(users.read())
    loggedin = login(name, password)
    if loggedin:
        bottle.response.set_header('Set-Cookie', f'login={urllib.parse.quote(str(json.dumps([name, password])))}')
        bottle.redirect('/')
    else:
        bottle.abort(403, 'Failed to authenticate.')

def login(name, password):
    loggedin  = False
    pwencoded = str.encode(password)
    users     = open('users.json', 'r')
    userslist = json.loads(users.read())
    #print(name)
    for i in userslist:
        if i['user'].lower() == name.lower():
                if bcrypt.checkpw(str.encode(password), str.encode(i['password'])):
                    loggedin = True
                else:
                    loggedin = False
        else:
            pass
    if loggedin:
        return True
    else:
        return False

@app.route('/login', method='GET')
def log_get():
    try:
        cook = urllib.parse.unquote(bottle.request.get_cookie("login"))
    except:
        cook = '["khldgfjhagfajgfhakgfjadhgladkgjhadgfkladjgfh", "2"]'
    cook = json.loads(cook)
    if login(cook[0], cook[1]):
        bottle.redirect('/')
    user = finduser(cook[0])
    if user['admin']:
        adpanelentry = '<li><a href="/apanel">Admin Panel</a></li>'
    else:
        adpanelentry = ''
    return (header.replace('PQOYIEBUTTONSHERE', '<li><a href="/login">Log in</a></li><li><a class="button" href="/signup">Sign up</a></li>') if not login(cook[0], cook[1]) else header.replace('PQOYIEBUTTONSHERE', f'<li><a href="/gtfo">Log out</a></li><li><a class="button" href="user">{cook[0]}</a></li>').replace('ADMINPANELHEREaa', adpanelentry)).replace('ADMINPANELHEREaa', adpanelentry) + '''
            <div class="centerText"><h3>Log In</h3></div>
            <form id="loginForm" action="/login" method="POST">
                <input name="user" type="text" placeholder="Username" />
                <input name="pw" type="password" placeholder="Password" />
                <input value="Log in" type="submit" />
            </form>
            
    ''' + endder
@app.route('/signup', method='POST')
def reg():
    bodytext = bottle.request.forms
    runcmd = subprocess.call(['python3', 'makeuser.py', bodytext.user, bodytext.pw, bodytext.inv])
    config_file = open('config.json', 'r')
    config = json.loads(config_file.read())
    if not config['registration_open']:
        bottle.abort(401, 'Registration is closed.')
    if runcmd == 120:
        return "A VoidCute name cannot be more than 16 characters"
    elif runcmd == 121:  # I feel like this might be a reference to something..
        return 'Usernames can only contain letters, digits, and underscores'
    elif runcmd == 122:
        return 'A user with that name already exists'
    elif runcmd == 123:
        return 'Your username cannot be empty'
    elif runcmd == 124:
        return 'Your password must be 8 characters or more'
    elif runcmd == 125:
        return 'GIVE ME A DAMN INVITE KEY.'
    else:
        #return f'Successful - welcome to VoidCute, {bodytext.user}!'
        bottle.response.set_header('Set-Cookie', f'login={urllib.parse.quote(str(json.dumps([bodytext.user, bodytext.pw])))}')
        bottle.redirect('/')

@app.route('/signup', method='GET')
def log_get():
    try:
        cook = urllib.parse.unquote(bottle.request.get_cookie("login"))
    except:
        cook = '["khldgfjhagfajgfhakgfjadhgladkgjhadgfkladjgfh", "2"]'
    cook = json.loads(cook)
    config_file = open('config.json', 'r')
    config = json.loads(config_file.read())
    if login(cook[0], cook[1]):
        bottle.redirect('/')

    user = finduser(cook[0])
    if user['admin']:
        adpanelentry = '<li><a href="/apanel">Admin Panel</a></li>'
    else:
        adpanelentry = ''
    return (header.replace('PQOYIEBUTTONSHERE', '<li><a href="/login">Log in</a></li><li><a class="button" href="/signup">Sign up</a></li>') if not login(cook[0], cook[1]) else header.replace('PQOYIEBUTTONSHERE', f'<li><a href="/gtfo">Log out</a></li><li><a class="button" href="user">{cook[0]}</a></li>').replace('ADMINPANELHEREaa', adpanelentry)).replace('ADMINPANELHEREaa', adpanelentry) + '''
        <div class="centerText"><h3>Sign Up</h3></div>
        <form id="registerForm" action="/signup" method="POST">
            <input name="user" type="text" placeholder="Username" />
            <input name="pw" type="password" placeholder="Password" />
            <input name="inv" type="text" placeholder="Invite Key" />
            <div class="centerText"><input value="Register" type="submit" /></div>
        </form>
    ''' if config['registration_open'] else f'Registration is closed. Ask the server admin <code>{config["webmaster"]}</code> for an account or to open registration.' + endder


def servstyle(servers, cook):
    cook = json.loads(cook)
    loggedin = login(cook[0], cook[1])
    user = finduser(cook[0])
    if user['admin']:
        adpanelentry = '<li><a href="/apanel">Admin Panel</a></li>'
    else:
        adpanelentry = ''
    buf = (header.replace('PQOYIEBUTTONSHERE', '<li><a href="/login">Log in</a></li><li><a class="button" href="/signup">Sign up</a></li>') if not login(cook[0], cook[1]) else header.replace('PQOYIEBUTTONSHERE', f'<li><a href="/gtfo">Log out</a></li><li><a class="button" href="user">{cook[0]}</a></li>').replace('ADMINPANELHEREaa', adpanelentry)).replace('ADMINPANELHEREaa', adpanelentry) + '<h3>Server list</h3>'
    buf = buf + '<table id="servers">'
    end = "</table>"
    for i in servers:
        if servers[i]['heartbeat_expiry'] <= time.time():
            del servers[i]
            return 127
        if servers[i]['public'] == 'True':
            if loggedin:
                buf += f'<tr class="server"><td><strong><a href="{"/play?ip=" + servers[i]["ip"] + "&port=" + servers[i]["port"] + "&user=" + cook[0] + "&ver=" + md5((servers[i]["salt"] + cook[0]).encode("utf-8")).hexdigest()}">{servers[i]["name"]}</a></strong></td><td class="players">[0/{servers[i]["max"]}]</td>'
            else:
                buf += f'<tr class="server"><td><strong>{servers[i]["name"]}</strong></td><td class="players">[0/{servers[i]["max"]}]</td>'
            buf += '</tr>'
    finish = buf + end + endder
    return finish

def servstyle_cubic(servers, cook):
    b = 0
    buf = {"servers": []}
    loggy = cook.split('XZBNA')
    loggedin = login(loggy[1], loggy[2])
    for i in servers:
        if servers[i]['heartbeat_expiry'] <= time.time():
            del servers[i]
            return 127
        start_time = time.perf_counter()
        region = gi.country_code_by_addr(servers[i]['ip'])
        if not bool(region):
            region = "KP"
        buf['servers'].append({'hash': servers[i]['salt'], 'maxplayers': servers[i]['max'], 'name': servers[i]['name'], 'players': servers[i].get('users', 0), 'uptime': 0, 'country_abbr': region, 'featured': True})
        if loggedin:
            buf['servers'][b].update({'ip': servers[i]['ip'], 'port': servers[i]['port'], 'mppass': md5((servers[i]["salt"] + loggy[1]).encode("utf-8")).hexdigest()})
        try:
            buf['servers'][b].update({'software': servers[i]['software']})
        except:
            pass
        b += 1
        end_time = time.perf_counter()
        elapsed = (end_time - start_time) * 1000
        print(f'server processed (took {elapsed} ms)')
    return buf

@app.route('/servers')
def serv():
    start_time = time.perf_counter()
    #return servers
    try:
        cook = urllib.parse.unquote(bottle.request.get_cookie("login"))
    except:
        cook = '["khldgfjhagfajgfhakgfjadhgladkgjhadgfkladjgfh", "2"]'
    cookl = json.loads(cook)
    user = finduser(cookl[0])
    print(user)
    if user['banned']:
        bottle.redirect('/moderation')
    operation = servstyle(servers, cook)
    if operation == 127:
        print('have to render again')
        operation = servstyle(servers, cook)
    end_time = time.perf_counter()
    elapsed = (end_time - start_time) * 1000
    print(f'render processed (took {elapsed} ms)')
    return operation

@app.route('/server/<shash>')
def serv(shash):
    #return servers
        
    try:
        cook = urllib.parse.unquote(bottle.request.get_cookie("login"))
    except:
        cook = '["khldgfjhagfajgfhakgfjadhgladkgjhadgfkladjgfh", "2"]'
    serv = servers[shash]
    #print(cook)
    cook = json.loads(cook)
    #print(login(cook[0], cook[1]))
    return f'''
    {serv}
    <h1>VoidCute Server</h1>
    <h3>{serv['name']}</h3>
    <p>Runs on the {serv['software']} software<br>
    {'Public server' if serv['public'] == True else 'Private server'}<br>
    {f'<a href="mc://{serv["ip"]}:{serv["port"]}/{cook[0]}/{md5((serv["salt"] + cook[0]).encode("utf-8")).hexdigest()}">Direct link</a>' if login(cook[0], cook[1]) else ''}
    </p>
    '''
    """
    bottle.abort(410, 'Deprecated for right now..')
    """

@app.route('/gtfo')
def logout():
    try:
        cook = urllib.parse.unquote(bottle.request.get_cookie("login"))
    except TypeError:
        bottle.abort(403)
    bottle.response.set_cookie('login', '')
    bottle.redirect('/')

@app.route('/user')
def usercfgpage():
    try:
        cook = urllib.parse.unquote(bottle.request.get_cookie("login"))
    except TypeError:
        bottle.abort(403)
    cook = json.loads(cook)
    user = finduser(cook[0])
    if user['banned']:
        bottle.redirect('/moderation')
    if login(cook[0], cook[1]):
        pass
    else:
        bottle.abort(403)
    return (
f'''
<h1>cannot be ASSED to make this page look good rn fuck youy</h1>
<p>YOU ARE: {cook[0]}</p>
<form action="/user/dress" method="POST" enctype="multipart/form-data">
    <input type="file" name="upload">
    <input type="submit" value="ok, change skin">
</form>
'''
)

@app.route('/user/dress', method='POST')
def usercfgpage():
    try:
        cook = urllib.parse.unquote(bottle.request.get_cookie("login"))
    except TypeError:
        bottle.abort(403)
    cook = json.loads(cook)
    user = finduser(cook[0])
    if user['banned']:
        bottle.redirect('/moderation')
    category = bottle.request.forms.category
    upload = bottle.request.files.get('upload')
    print(upload)
    tmppath = f'skins/tmp/{randint(10000000, 99999999)}.bin'
    upload.save(tmppath)
    upload_filetype = imghdr.what(tmppath)
    if upload_filetype == "png":
        if os.path.exists(f'skins/{cook[0]}.png'):
            os.remove(f'skins/{cook[0]}.png')
        upload.save(f'skins/{cook[0]}.png')
        os.remove(tmppath)
        bottle.redirect('/user')
    else:
        os.remove(tmppath)
        bottle.abort(403, 'Very invalid, what is wrong with you?')

# ClassiCube support
@app.route('/api/servers')
def servraw(token='b'):
    #return servers
    try:
        cook = urllib.parse.unquote(bottle.request.get_cookie("session"))
    except TypeError:
        cook = f'XZBNAfXZBNAf'
    bottle.response.content_type = 'application/json'
    operation = servstyle(servers, cook)
    if operation == 127:
        print('have to render again')
        operation = servstyle_cubic(servers, cook)
    return json.dumps(operation)

@app.route('/api/login', method='GET')
def classi_log_get():
    print('user get /api/login')
    bottle.response.set_header('set-cookie', f'session=fuck; HttpOnly; Path=/')
    return json.dumps({'token': 'fuck_off'})

@app.route('/api/login', method='POST')
def classi_log_post():
    print('user post /api/login')
    cook = bottle.request.get_cookie("session")
    bodytext = bottle.request.params
    buf = {}
    #print('asdfasdfasfafs22222222\n')
    #print(sha256(bodytext.password.encode("utf-8")).hexdigest())
    print(bodytext.get('username'))
    print(bodytext.get('password'))
    user = finduser(bodytext.get('username'))
    if user['banned']:
        bottle.abort(401)
    if login(bodytext.get('username'), bodytext.get('password')):
        buf['authenticated'] = True
        buf['username'] = bodytext.get('username')
        buf['password'] = bodytext.get('password')
        buf['token'] = f'XZBNA{bodytext.username}XZBNA{bodytext.password}'
        token = f'XZBNA{bodytext.username}XZBNA{bodytext.password}'
        bottle.response.set_header(f'set-cookie', f'session={token}; HttpOnly; Path=/')
        return json.dumps(buf)
    else:
        buf['authenticated'] = False
        buf['username'] = None
        buf['errors'] = ['username', 'password']
        return json.dumps(buf)

def smartchk_existingserver(server):
    #print('DEBUGGING VALUES: ')
    #print(servers)
    #print(type(servers))
    #print(server)
    #print(type(server))
    #print('\n')
    for i in servers:
        #print('index in servers:')
        #print(i)
        if server['ip'] == servers[i]['ip'] and server['port'] == servers[i]['port']:
            return servers[i]['salt']
        else:
            pass
    return None


@app.route('/heartbeat.jsp', method='GET')
@app.route('/heartbeat.jsp', method='POST')
def hb():
    bodytext = bottle.request.params
    print(f'{list(bodytext.items())}')

    #bodysplit = str(bodytext).replace("b'", '').removesuffix("'")
    #bodysplit = bodysplit.split('&')
    #bodysplit = [i.split('=') for i in bodysplit]
    #print(bodysplit)

    sname    = bodytext.name
    sip      = bottle.request.environ.get('HTTP_X_FORWARDED_FOR') or bottle.request.environ.get('REMOTE_ADDR')
    sport    = bodytext.port
    splaymax = bodytext.max
    spublic  = bodytext.public
    ssalt    = bodytext.salt
    susers   = bodytext.users
    tmp = {'name': sname, 'ip': sip, 'port': sport, 'max': splaymax, 'public': spublic, 'salt': ssalt, 'featured': True, 'users': susers, 'heartbeat_expiry': int(time.time()+45)}
    try:
        check = smartchk_existingserver(tmp)
    except:
        print('check failed')
        check = None
    if check is None:
        pass
    else:
        del servers[check]
    servers[ssalt] = {'name': sname, 'ip': sip, 'port': sport, 'max': splaymax, 'public': spublic, 'salt': ssalt,
                      'featured': True, 'users': susers, 'heartbeat_expiry': int(time.time() + 45)}
    if 'software' in bodytext:
        ssoftware = bodytext.software
        servers[ssalt]['software'] = ssoftware
    #print(f'created {ssalt} ')
    #hi = threading.Thread(target=kalive_task, args=[ssalt, servers[ssalt]['rnd']])
    #hi.start()
    host = bottle.request.urlparts.netloc
    return f'http://{host}/server/{ssalt}'

# thank you to https://github.com/ClassiCube/ClassiCube/blob/master/doc/hosting-flask.md
@app.route('/play')
def play():
    bodytext = bottle.request.query
    user = bodytext.get('user') or 'Singleplayer'
    ver  = bodytext.get('mppass') or ''
    addr = bodytext.get('ip')
    port = bodytext.get('port') or '25565'

    if addr:
        args = "['%s', '%s', '%s', '%s']" % (user, ver, addr, port)
    else:
        args = "['%s']" % user
    return bottle.jinja2_template('web/template/play.htm', game_args=args)

def kalive_task(salt, rnd):
    time.sleep(29.9)
    if servers[salt]['rnd'] == rnd:
        del servers[salt]
    #print(f'removed {salt}')
    return

@app.route('/apanel')
def adminpanel():
    try:
        cook = urllib.parse.unquote(bottle.request.get_cookie("login"))
    except:
        cook = '["khldgfjhagfajgfhakgfjadhgladkgjhadgfkladjgfh", "2"]'
    users_read = open('users.json', 'r')
    users = json.loads(users_read.read())
    users_read.close()
    cook = json.loads(cook)
    listofusers = ''
    current_user = {'user': '', 'password': '', 'admin': False}
    for i in users:
        listofusers += f"{i['user']}<br>"
        if i['user'].lower() == cook[0].lower():
            current_user = i
    if current_user['admin']:
        pass
    else:
        bottle.redirect('/')
    return ((header.replace('PQOYIEBUTTONSHERE', '<li><a href="/login">Log in</a></li><li><a class="button" href="/signup">Sign up</a></li>') if not login(cook[0], cook[1]) else header.replace('PQOYIEBUTTONSHERE', f'<li><a>Logged in as {cook[0]}</a></li><li><a class="button" href="/gtfo">Log out</a></li>').replace('ADMINPANELHEREaa', '')) +
            f"<h3>VoidCute admin panel</h3>"
            f"<p>Users in the database:</p><p>{listofusers}</p>"
            f'<form id="registerForm" action="/apanel/ban" method="POST">'
            f'<input type="text" placeholder="Username to ban" name="user">'
            f'<input type="text" placeholder="Reason to provide" name="reason">'
            f'<input type="submit" value="Ban!!">'
            f'</form>'
            f'<form id="registerForm" action="/apanel/unban" method="POST">'
            f'<input type="text" placeholder="Username to unban" name="user">'
            f'<input type="submit" value="Unban..">'
            f'</form>'
            f'<h3>Debugging</h3>'
            f'<h2>Servers JSON</h2>'
            f'<p>{servers}</p>'
            f'<h2>Config JSON</h2>'
            f'<p>{config}</p>'
            +
            endder)

@app.route('/apanel/remove', method='POST')
def adminremove():
    bottle.abort(410, 'Deprecated due to the nature of Classic Protocol, sorry.')

@app.route('/apanel/usrchange', method='POST')
def adminchange():
    bottle.abort(410, 'Deprecated due to the nature of Classic Protocol, sorry.')

@app.route('/apanel/ban', method='POST')
def adminban():
    try:
        cook = urllib.parse.unquote(bottle.request.get_cookie("login"))
    except:
        cook = '["khldgfjhagfajgfhakgfjadhgladkgjhadgfkladjgfh", "2"]'
    users_read = open('users.json', 'r')
    users = json.loads(users_read.read())
    users_read.close()
    cook = json.loads(cook)
    for i in users:
        if i['user'].lower() == cook[0].lower():
            current_user = i
    if current_user['admin']:
        pass
    else:
        bottle.redirect('/')
    bodytext  = bottle.request.forms
    name      = bodytext.user
    reason    = bodytext.reason
    users_read = open('users.json', 'r')
    users = json.loads(users_read.read())
    users_read.close()
    b = 0
    for i in users:
        if i['user'].lower() == name.lower():
            users[b]['banned'] = True
            users[b]['ban_reason'] = reason
        b += 1
    users_write = open('users.json', 'w')
    users_write.write(json.dumps(users))
    users_write.close()
    return 'Finished'

@app.route('/apanel/unban', method='POST')
def adminunban():
    try:
        cook = urllib.parse.unquote(bottle.request.get_cookie("login"))
    except:
        cook = '["khldgfjhagfajgfhakgfjadhgladkgjhadgfkladjgfh", "2"]'
    users_read = open('users.json', 'r')
    users = json.loads(users_read.read())
    users_read.close()
    cook = json.loads(cook)
    for i in users:
        if i['user'].lower() == cook[0].lower():
            current_user = i
    if current_user['admin']:
        pass
    else:
        bottle.redirect('/')
    bodytext  = bottle.request.forms
    name      = bodytext.user
    users_read = open('users.json', 'r')
    users = json.loads(users_read.read())
    users_read.close()
    b = 0
    for i in users:
        if i['user'].lower() == name.lower():
            users[b]['banned'] = False
        b += 1
    users_write = open('users.json', 'w')
    users_write.write(json.dumps(users))
    users_write.close()
    return 'Finished'

app.run(host='0.0.0.0', port=34717)