#아이피의 군영향성평가를위한 CVE의 PHP에대한 공격인지여부에 대한 조회.
#정보보호 19-4기 박재용<scorpion@dgu.ac.kr>

from urllib.request import urlopen
from bs4 import BeautifulSoup
import time

start = time.time()#start time
print('''사용방법: 
1.조회를 희망하는 CVE들을 cve.txt파일에 엔터를 구분자로 차례대로 입력한다.
2.결과로 output.txt 파일이 생성되며, 해당 파일은 json형식으로 저장되어있다.

업데이트.
기존 json 출력에서 가독성이 떨어짐을 느끼고 간단하게 변경.
''')

rf= open("cve.txt",'r')#파일 읽기
f= open("output.txt",'w')#쓸 파일 입력


tempString=rf.read()
userInput=tempString.split('\n') #오리지널 아이피
targetPage=[] #조회하는 유알엘
resultReports=[]
baseUrlObject="https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword="

length = len(userInput)
for i in userInput:
    targetPage.append(baseUrlObject+i)
dic ={}
counter = 0;
kaisuu=0;
countIp=0;
for i in targetPage:
    counter+=1
    #if(counter==30):
        #time.sleep(17)
        #print("진행경과",float((kaisuu+1)*30)/float(len(targetPage)))
        #counter =0
        #kaisuu+=1
    print(i)
    html = urlopen(i)
    bsObject = BeautifulSoup(html,"html.parser")
    
    theNumOfReports = str(bsObject.select("#TableWithRules > table"))
    print(theNumOfReports)
    resultNum =""
    print(theNumOfReports.find("PHP"))
    
    if(theNumOfReports.find("PHP")!=-1):
        countIp+=1
        print(countIp," / ",length)
        resultNum="PHP related Vulnerability"
    else:
        resultNum="None"
    resultReports.append(resultNum)
        
    
        #print(resultNum)
#print(resultReports)


#dic=dict(zip(userInput,resultReports))
for i in range(len(userInput)):
    f.write(str(userInput[i])+" : "+str(resultReports[i])+"\r")
print("파일 추출완료","소요시간",time.time()-start)
#f.write(str(dic))
f.write(str(time.time()-start)+"초 소요.")
f.close()
