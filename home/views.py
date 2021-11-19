from json import dump
from django import http
from django.http.response import HttpResponse
from django.shortcuts import render
import socket
import geocoder
from home.models import Url
# Create your views here.

def index(request):
    return render(request, 'home/index.html')

def result(request):
    text=request.POST['link'].lower()
    try:
        #nm=request.GET['url']
        import tldextract
        do=tldextract.extract(text).domain
        sdo=tldextract.extract(text).subdomain
        suf=tldextract.extract(text).suffix
        if not text.startswith('http://') and not text.startswith('https://'):
            return render(request,"home/404.html")
        if text.startswith('https://malicious-url-detectorv5.herokuapp.com/') or text.startswith('https://mudv9.eu-gb.cf.appdomain.cloud/')  :
            return render(request,'home/result.html',{'result':'Real-time analysis successfull','f2':'Legtimate','mal': True,'text':text,'name':"The Legions",
                        'org':"The Legions",
                        'add':"New Delhi",
                        'city':"New Delhi",
                        'state':"New Delhi",
                        'ziip':"201301",
                        'country':"India",'emails':"thelegions@gmail.com",
                        'dom':"Hidden For Privacy",'rank':"Hidden For Privacy","tags":"Hidden For Privacy","registrar":"Hidden For Privacy","var13":"NA","varab":"NA","var11":"NA","var10":"NA","var5":"NA","var4":"NA","var3":"NA"})

        elif text.startswith('https://www.youtube.com/results?'):
                        return render(request,'home/result.html',{'result':'Real-time analysis successfull','f2':'Legtimate','mal': True,'text':text,'name':"NA for youtube search results",
                                'org':"NA for youtube search results",
                                'add':"NA for youtube search results",
                                'city':"NA for youtube search results",
                                'state':"NA for youtube search results",
                                'ziip':"NA for youtube search results",
                                'country':"NA for youtube search results",'emails':"NA for youtube search results",
                                'dom':"NA for youtube search results",'rank':"NA for youtube search results","tags":"NA for youtube search results","registrar":"NA for youtube search results","var13":"NA for youtube search results","varab":"NA for youtube search results","var11":"NA for youtube search results","var10":"NA for youtube search results","var5":"NA for youtube search results","var4":"NA for youtube search results","var3":"NA for youtube search results"})


        elif text.startswith('https://www.google.com/search?q='):
                return render(request,'home/result.html',{'result':'Real-time analysis successfull','f2':'Legtimate','mal': True,'text':text,'name':"NA for google search",
                        'org':"NA for google search",
                        'add':"NA for google search",
                        'city':"NA for google search",
                        'state':"NA for google search",
                        'ziip':"NA for google search",
                        'country':"NA for google search",'emails':"NA for google search",
                        'dom':"NA for google search",'rank':"NA for google search","tags":"NA for google search","registrar":"Hidden For Privacy","var13":"NA for google search","varab":"NA for google search","var11":"NA for google search","var10":"NA for google search","var5":"NA for google search","var4":"NA for google search","var3":"NA for google search"})


        elif text.startswith('https://www.youtube.com/watch?v='):
            return render(request,'home/result.html',{'result':'Real-time analysis successfull','f2':'Legtimate','mal': True,'text':text,'name':"NA for Youtube search",
                        'org':"NA for Youtube search",
                        'add':"NA for Youtube search",
                        'city':"NA for Youtube search",
                        'state':"NA for Youtube search",
                        'ziip':"NA for Youtube search",
                        'country':"NA for Youtube search",'emails':"NA for Youtube search",
                        'dom':"NA for Youtube search",'rank':"NA for Youtube search","tags":"NA for Youtube search","registrar":"Hidden For Privacy","var13":"NA for Youtube search","varab":"NA for Youtube search","var11":"NA for Youtube search","var10":"NA for Youtube search","var5":"NA for Youtube search","var4":"NA for Youtube search","var3":"NA for Youtube search"})

        elif (text.startswith('https://www.google.com/search?q=')==False ):

            if text.startswith('https://') or text.startswith('http://'):
                var13="Not Applicable"
                varab="Not Applicable"
                var11="Not Applicable"
                var10="Not Applicable"
                var5="Not Applicable"
                var4="Not Applicable"
                var3="Not Applicable"

                if len(text)<=9:
                    return render(request,'errorpage.html')
                aburl=-1
                digits="0123456789"
                if text[8] in digits:
                    oneval=-1
                else:
                    oneval=1    
                if len(text)>170:
                    secval=-1
                else:
                    secval=1  
                if "@" in text:
                    thirdval=-1
                    var3="'@' detected"
                else:
                    thirdval=1       
                    var3="No '@' detected"
                k=text.count("//")          
                if k>1:
                    fourthval=-1
                    var4="More Redirects"
                else:
                    fourthval=1
                    
                if "-" in do or "-" in sdo:
                    fifthval=-1
                    var5="Prefix-Suffix detected"
                else:
                    fifthval=1 
                    var5="No Prefix-Suffix detected"     

                if "https" in text:
                    sixthval=1
                else:
                    sixthval=-1
                temp=text
                temp=temp[6:]
                k1=temp.count("https")

                if k1 >=1:
                    seventhval=-1
                else:
                    seventhval=1
                if "about:blank" in text:
                    eighthval=-1
                else:
                    eighthval=1
                if "mail()" or "mailto:" in text:
                    ninthval=-1
                else:
                    ninthval=1
                re=text.count("//")          
                if re>3:
                    tenthval=-1
                    var10="redirects more than 2"
                else:
                    tenthval=1    
                    var10=f"{re-1} redirects detected"

                import whois

                from datetime import datetime

                url=text
                #code replaced whois
                # 
                """try:"""
                d=-1
                try:
                    res=whois.whois(url)
                    cpyres=res
                except:
                    print("getaddrerrror DNE")
                    d=0
                    name="Not found in WHOIS database"
                    org="Not found in WHOIS database"
                    add="Not found in WHOIS database"
                    city="Not found in WHOIS database"
                    state="Not found in WHOIS database"
                    ziip="Not found in WHOIS database"
                    country="Not found in WHOIS database"
                    emails="Not found in WHOIS database"
                    dom="Not Found in WHOIS database"
                    registrar="Not Found in WHOIS database"
                if d!=0:    
                    try:
                        if len(res.creation_date)>1:
                            a=res['creation_date'][0]
                            b=datetime.now()
                            c=b-a
                            d=c.days
                    except:
                        a=res['creation_date']
                        b=datetime.now()
                        c=b-a
                        d=c.days
                """except:
                    print("getaddrerrror DNE")
                    d=0"""

                
                # kiểm tra độ tuổi của domain
                if d>365:
                    eleventhval=1
                    aburl=1
                    var11=f"Domain age is {d} days" 
                elif d<=365:
                    eleventhval=-1
                    aburl=-1
                    var11=f"Domain age working less than a year, {d} days"
        



                if aburl==-1:
                    twelthval=-1
                    varab="Abnormal URL detected"
                else:
                    twelthval=1 
                    varab="Website Registered on WHOIS Database"
                #print (twelthval,eleventhval,aburl,d)    
                import urllib.request, sys, re
                import xmltodict, json
                # kiểm tra rank của trang web
                try:
                    
                    xml = urllib.request.urlopen('http://data.alexa.com/data?cli=10&dat=s&url={}'.format(text)).read()

                    result = xmltodict.parse(xml)

                    data = json.dumps(result).replace("@","")
                    data_tojson = json.loads(data)
                    url = data_tojson["ALEXA"]["SD"][1]["POPULARITY"]["URL"]
                    rank= int(data_tojson["ALEXA"]["SD"][1]["POPULARITY"]["TEXT"])
                    #print ("rank",rank)
                    if rank<=150000:
                        thirt=1
                    else:
                        thirt=-1
                        var13=f"Ranked {rank} in Alexa Database, Larger index in alexa database detected!!"
                    #print (thirt)    
                except:
                    thirt=-1 
                    rank=-1
                    ##############var13="Larger index in alexa database"
                    var13="Not indexed in alexa database"
                    #print (rank)                  
                import joblib
                filename = 'phish_trainedv7mud0.001.sav'
                loaded_model = joblib.load(filename)

                arg=loaded_model.predict(([[oneval,secval,thirdval,fourthval,fifthval,seventhval,eighthval,ninthval,tenthval,eleventhval,twelthval,thirt]]))
                #print (arg[0])
                import whois
                url=text
                #print (res)
                #res=whois.whois(url)
                if (d!=0):
                    name=res.domain_name
                    #print (res.domain_name)
                    org=res.org
                    #print (res.org)
                    add=res.address
                    #print (res.address)
                    city=res.city
                    #print (res.city)
                    state=res.state
                    #print (res.state)
                    ziip=res.zipcode
                    #print (res.zipcode)
                    country=res.country
                    #print (res.country)
                    emails=res.emails
                    #print (res.emails)
                    dom=res.domain_name
                    #print (res.domain_name)   
                    registrar=res.registrar             
                else:
                    name="Not found in database"
                    org="Not found in database"
                    add="Not found in database"
                    city="Not found in database"
                    state="Not found in database"
                    ziip="Not found in database"
                    country="Not found in database"
                    emails="Not found in database"
                    dom="Not Found"
                    registrar="Not Found"

                
                    

                if aburl==-1 and rank==-1 :
                    arg[0]=-1
                    #phishing

                if arg[0]==1:
                    te="Legitimate"
                else:
                    te="Malicious"  
                if arg[0] == 1:
                    mal = True
                else:
                    mal = False      

                #print (name,org,add,city,state,ziip,country,emails,dom)


                from json.encoder import JSONEncoder
                final_entity = { "predicted_argument": [int(arg[0])]}
                # directly called encode method of JSON
                #print (JSONEncoder().encode(final_entity)) 
                domage=str(d)+' '+'days'
                redir=k-1

                if isinstance(cpyres.domain_name,str)==True:
                    d=cpyres.domain_name
                elif isinstance(cpyres.domain_name,list)==True:
                    d=cpyres.domain_name[0]   


                #print (d)

                try:

                    ip=socket.gethostbyname_ex(d)
                    ipadd=(ip[2][0])
                    
                    g=geocoder.ip(ipadd)
                    ipcity=g.city
                    
                    ipstate=g.state
                    
                    ipcountry=g.country
                
                    iplatitude=g.latlng[0]
                    
                    iplongitude=g.latlng[1]
                    
                except:
                    ipadd="Not Found"
                    #print (ipadd)
                    
                    ipcity="Not Found"
                    #print (city)
                    ipstate="Not Found"
                    #print (state)
                    ipcountry="Not Found"
                    #print (country)
                    iplatitude="Not Found"
                    #print (g.latlng)
                    iplongitude="Not Found"
                    #print (latitude)
                    #print (longitude)
                '''print (ipadd)
                print (ipcity)
                print (ipstate)
                print (ipcountry)
                print (iplatitude)
                print (iplongitude)
                '''


                obj = Url()
                obj.result = te 
                return HttpResponse(obj)

                obj.save()
                #print (dom,rank)

                tags = [name,org,state,add,city,ziip,country,emails,dom,rank,domage,varab,redir,var3,var5]

                tags = list(filter(lambda x: x!="Not Found",tags))
                tags.append(text)
                obj.link = text
                obj.add = add
                obj.state = state
                obj.city = city
                
                #obj.ziip = res['zip_code']
                obj.country = country 
                obj.emails = emails
                obj.dom = dom
                obj.org = org
                obj.rank = rank
                obj.registrar=registrar
                obj.domage=domage
                obj.varab=varab
                obj.redir=redir
                obj.var3=var3
                obj.var5=var5
                obj.ipadd=ipadd
                obj.ipcity=ipcity
                obj.ipstate=ipstate
                obj.ipcountry=ipcountry
                obj.iplatitude=iplatitude
                obj.iplongitude=iplongitude

                obj.save()
                nm=name
                oor=org
                em=emails
                # print (add)
                
                if add!=None:
                    if add and len (add)==1:
                        add=add.replace(",","")
                    elif len(add)>1:
                        add="".join(add)
                    #print (add)     
                
                name="".join(name)
                #print (name)
                if emails!=None:
                    emails="".join(emails)
                if org!=None:    
                    org=org.replace(",","")
                #print (org)
                '''print (dom)'''
                dom="".join(dom)
                #print (dom)
                if registrar:
                    registrar=registrar.replace(",","")
                #print (registrar)
                #print (emails)
                #print(city)
                import datetime
                import csv
                with open ('static//dataset.csv','a',encoding="utf-8") as res:        
                    writer=csv.writer(res)           
                    s="{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n".format(text,te,str(name),
                        str(org).replace(",",''),
                        str(add).replace(",",''),
                        str(city).replace(",",''),
                        str(state).replace(",",''),
                        str(ziip).replace(",",''),
                        str(country).replace(",",''),str(emails).replace(",",''),
                        str(dom).replace(",",''),rank,str(registrar).replace(",",''),str(datetime.datetime.now()))
                    res.write(s)      
            
                return render(request,'result.html',{'result':'Real-time analysis successfull','f2':te,'mal': mal,'text':text,'name':nm,
                        'org':oor,
                        'add':add,
                        'city':city,
                        'state':state,
                        'ziip':ziip,
                        'country':country,'emails':em,
                        'dom':d,'rank':rank,'registrar':registrar,"tags":tags,"var13":var13,"varab":varab,"var11":var11,"var10":var10,"var5":var5,"var4":var4,"var3":var3,"ipadd":ipadd,'ipcity':ipcity,'ipstate':ipstate,'ipcountry':ipcountry,'iplatitude':iplatitude,'iplongitude':iplongitude})



        else:
            return render(request,'home/404.html')  
    except:
        return render(request,'home/404.html')  
        #website DNE or feature extraction cannot be completed
        '''return render(request,'result.html',{'result':'Real-time analysis successfull','f2':'Legtimate','mal': True,'text':text,'name':"NA",
                                'org':"NA",
                                'add':"NA",
                                'city':"NA",
                                'state':"NA",
                                'ziip':"NA",
                                'country':"NA",'emails':"NA",
                                'dom':"NA",'rank':"NA","tags":"NA","registrar":"NA","var13":"NA","varab":"NA","var11":"NA","var10":"NA","var5":"NA","var4":"NA","var3":"NA","ipadd":"NA",'ipcity':"NA",'ipstate':'NA','ipcountry':'NA','iplatitude':'NA','iplongitude':'NA'})'''
    