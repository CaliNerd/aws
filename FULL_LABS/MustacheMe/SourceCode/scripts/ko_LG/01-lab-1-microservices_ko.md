# 실습 0 - 사전 조건 및 qwikLAB 설정

**개요**

본 일일 부트 캠프에서는 Amazon Web Services를 사용하여 컨테이너식 마이크로 서비스 모음으로 구성된 애플리케이션을 설계, 배포, 실행 및 관리하는 방법을 알아봅니다. Docker를 활용하여 컨테이너를 구축하고, EC2 Container Service (ECS)를 사용하여 이러한 컨테이너를 배포 및 실행하게 됩니다. 또한, 서비스 검색을 위해 다른 AWS 서비스를 탄력적 로드 밸런서, Cloudwatch 모니터링, 타사 솔루션인 HashiCorps Consul 등과 같은 마이크로 서비스 아키텍처와 통합하는 방법을 배웁니다.

부트 캠프에는 다음과 같은 몇 가지 실습이 포함됩니다.

-   사전 조건 및 qwikLABS 설정(지금 읽고 있는 안내서)

-   첫 번째 컨테이너를 만들고 실행하기

-   마이크로 서비스가 활성화된 애플리케이션 구성하기

-   서비스 스케줄러를 사용하여 Amazon ECS에서 마이크로 서비스 실행하기

-   Amazon ECS에서 배치 작업자 실행하기

-   Amazon ECS에서 서비스 검색 및 원격 측정하기

## qwikLAB이란 무엇입니까?

qwikLAB은 부트 캠프를 위해 AWS 서비스에 액세스할 수 있도록 해주며, 부트 캠프 기간 동안 사용할 AWS 계정의 사용자 이름과 암호를 제공합니다. 이 계정과 관련된 모든 비용은 부트 캠프 비용에 포함되어 있습니다. **부트 캠프 동안 사용하는 AWS 서비스에 대한 비용은 청구되지 않습니다.**

**필수 조건**

본 실습에는 다음 사전 조건이 필요합니다.

-   Microsoft Windows, Mac OS X 또는 Linux (Ubuntu, SuSE, Red Hat)가 실행되며 Wi-Fi가 되는 노트북 사용

-   iPad나 태블릿 디바이스로는 qwikLABS 실습 환경에는 액세스가 안되지만, 수강생 안내서는 볼 수 있습니다.

-   Microsoft Windows 사용자의 경우, 컴퓨터의 관리자 권한이 필요합니다.

-   Chrome, Firefox 또는 IE9과 같은 인터넷 브라우저(IE9 이전 버전은 지원 안 됨)

-   PuTTY와 같은 SSH 클라이언트

**기간**

본 실습은 약 10분 정도가 소요됩니다.

## qwikLAB 시작하기

**개요**

먼저 qwikLABS 계정을 생성해야 합니다. ***본 부트 캠프를 등록할 때와 동일한 이메일 주소를* 사용하여 qwikLABS에 등록합니다.** 로그인할 수 있는 qwikLABS 계정이 이미 있는 경우, 이 단계를 건너뛰고 로그인하십시오.

- **QwikLABS 계정 생성**

	- 웹 브라우저에서, 강사가 제공한 qwikLABS URL로 이동합니다.

	- 새로운 계정 생성 섹션을 완료합니다.

	- 등록이 성공적으로 완료되면 qwikLABS에서 확인 이메일을 받게 됩니다.

- **실습 시작**
<ol type='a'>
<li>qwikLABS에 등록한 후 로그인하면 부트 캠프용 링크가 보일 것입니다.</li>
<li>"Start Lab" 버튼을 클릭합니다.</li>
<li>Microsoft Windows를 사용하는 경우, 이 단계를 건너뛰고 다음 단계(1.2.4)로 진행하십시오. 사용하지 않는 경우에는 qwikLABS에서 PEM 파일을 다운로드합니다.</li>
<li>*참고*: SSH가 원격 접속을 허용하도록 하려면 다운로드한 PEM 파일의 권한을 변경해야 합니다. 다음 명령으로 OSX/Linux/Git Bash에서 올바른 권한을 설정합니다.

			chmod 600 <해당 PEM 파일>
</li><li>(Windows만 해당) Windows 사용자는 SSH로 EC2 인스턴스에 접속하려면 putty.exe 애플리케이션(또는 이와 유사한 것)을 사용해야 합니다. PuTTY는 PPK 형식의 키가 필요합니다.

	![](https://us-west-2-aws-staging.s3.amazonaws.com/awsu-bootcamp/AWS-300-RCM/v3.0/lab-1-microservices/scripts/images/lab0_image1.png)</li>
<li>**다음은 PuTTY를 사용하여 인스턴스를 구성하고 접속하는 절차입니다.**</li>
<ol type=1>
<li>**PuTTY**를 시작합니다. 즉 Windows 시작 메뉴에서 모든 프로그램 → PuTTY → PuTTY를 선택합니다. 대화 상자가 열리고 왼쪽에 Category 메뉴가 표시됩니다. 오른쪽에는 PuTTY 세션의 기본 옵션이 표시됩니다. Host Name 필드에 인스턴스의 퍼블릭 DNS 이름 또는 퍼블릭 IP 주소를 입력합니다. DNS 이름 또는 퍼블릭 IP 주소 앞에 ec2-user@을 붙여서 ec2-user로 자동 로그인되도록 할 수도 있습니다. 오늘 시작하는 모든 인스턴스에 대해 이 사용자를 사용할 것입니다.

	![](https://us-west-2-aws-staging.s3.amazonaws.com/awsu-bootcamp/AWS-300-RCM/v3.0/lab-1-microservices/scripts/images/lab0_image2.png)</li>
<li>Category 메뉴의 Connection에서 **SSH**와 Auth를 차례대로 클릭합니다. SSH 인증을 제어하는 옵션이 표시됩니다. Browse를 클릭하고 이 워크샵을 시작할 때 생성한 PuTTY 프라이빗 키 파일("qwikLABS-XXXXX-XXXXX.ppk")로 이동합니다.

	![](https://us-west-2-aws-staging.s3.amazonaws.com/awsu-bootcamp/AWS-300-RCM/v3.0/lab-1-microservices/scripts/images/lab0_image3.png)

	Open을 클릭합니다. SSH 세션 창이 열리고 연결하려는 호스트를 신뢰하는지 묻는 보안 알림이 PuTTY에 표시됩니다. Yes를 클릭합니다. SSH 세션을 시작하는 과정에서 ec2-user로 로그인하지 않은 경우 SSH 세션 창에서 해당 사용자로 로그인합니다. 참고: 프라이빗 키를 PuTTY 형식으로 변환할 때 암호문을 지정한 경우에는 인스턴스에 로그인할 때 그 암호문을 입력해야 합니다.</li>
<li>연결되면 아래와 같은 모습이 출력되어야 합니다(아래 스크린샷은 OSX 터미널입니다. PuTTY를 사용하는 경우에도 출력 내용은 거의 같습니다).

	![](https://us-west-2-aws-staging.s3.amazonaws.com/awsu-bootcamp/AWS-300-RCM/v3.0/lab-1-microservices/scripts/images/lab0_image4.png)

	적용 가능한 패키지에 대한 메시지가 출력되기도 합니다. 실습이기 때문에 이러한 것들을 적용하는 것까지는 신경 쓰지 않지만, 실제 시나리오에서는 보안 업데이트를 반드시 적용하고 가능하면 항상 최신 AMI를 사용해야 합니다.</li>
</ol>
</ol>


# 실습 1 - 마이크로 서비스

**개요**

본 일일 부트 캠프에서는 Amazon Web Services를 사용하여 컨테이너식
마이크로 서비스 모음으로 구성된 애플리케이션을 설계, 배포, 실행 및
관리하는 방법을 알아봅니다. Docker를 활용하여 컨테이너를 구축하고, EC2
Container Service (ECS)를 사용하여 이러한 컨테이너를 배포 및 실행하게
됩니다. 또한 기밀 공유를 위해 다른 AWS 서비스를 애플리케이션 로드
밸런서, Cloudwatch 모니터링, 타사 솔루션과 같은 마이크로 서비스
아키텍처와 통합하는 방법을 배웁니다.

부트 캠프에는 다음과 같은 몇 가지 실습이 포함됩니다.

-   사전 조건 및 QwikLABS 설정

-   첫 번째 컨테이너를 만들고 실행하기

-   마이크로 서비스가 활성화된 애플리케이션 구성하기

-   서비스 스케줄러를 사용하여 Amazon ECS에서 마이크로 서비스 실행하기

-   Amazon ECS에서 Auto Scaling 서비스 실행하기

-   Amazon ECS에서 서비스 검색, 기밀 공유 및 원격 측정하기

기간

본 실습은 약 45분 정도가 소요됩니다.

### EC2 인스턴스에 연결

**개요**

실습 활동 첫 번째 세션에 오신 것을 환영합니다. 강의를 듣는 것은 언제나
매력적인 일일 뿐 아니라 긴장감을 느끼게 합니다. 하지만 자신이 직접
해보는 것만큼 학습 효과가 큰 것은 없습니다. 그럼 이제 시작하겠습니다.

**시나리오**

Docker 기술을 다시 사용해볼 것입니다.

### CLI 인스턴스 DNS 이름 검색

**개요**

연결할 CLI 인스턴스는 CloudFormation 스택의 일부입니다. 그 이름을
찾아보겠습니다.

1. [1]브라우저에서 <https://console.aws.amazon.com/cloudformation/>으로
이동합니다.

2. [2]표에 보이는 것은 "스택"으로서, 기본적으로 JSON 형식의 템플릿에 따라
스핀업(spin up)된 인프라입니다. 이름에 “CliInstanceStack”이 있는 줄을
클릭합니다.

3. 하단 창에서 Outputs 탭을 클릭합니다.

4. PublicDnsName이라는 키와 이에 연결된 값을 찾습니다. 이것이 여러분이
사용할 DNS입니다. 다시 말해서 인스턴스의 DNS 는 **키**가
“PublicDnsName”인 **값**입니다.

5. 이것을 어딘가(예: 클립보드/버퍼)에 복사합니다.

Qwiklabs 내부에서, 즉 페이지 오른쪽에 있는 “Addl. Info”라는 파란색
탭에서 CLI 인스턴스 DNS 이름을 찾을 수도 있습니다.

### 인스턴스에 연결

6. [6]디렉터리를 .pem 파일이 있는 위치로 변경합니다.

7. SSH로 인스턴스에 접속합니다.

```
$ ssh –i <자신의 KEY.PEM> ec2-user@<자신의 EC2 인스턴스 퍼블릭 DNS 이름>```

### 컨테이너에서 모놀리식 애플리케이션 구축 및 실행

**개요**

이 작업에서는 Dockerfile을 사용하여 컨테이너를 만들고 컨테이너 1개를
실행 및 중지하는 방법에 대해 살펴봅니다.

**시나리오**

여러분은 현재 CLI 인스턴스에 접속되어 있습니다. 이제 여러분이 그 일부를
구성하고 있는 스타트업이 시작된 이후 구축된 애플리케이션 그대로
애플리케이션을 구축할 것입니다. 다만 그 애플리케이션을 컨테이너에 담는
경우는 해당되지 않습니다. 따라서 그것은 컨테이너 방식 모놀리스가 될
것입니다. 그 다음에는 앱과 관련된 작업을 약간 할 것입니다.

실제 상황에서는 리포지토리에서 소스 코드를 가져와야 할 수도 있지만, 시간
관계상 최신 버전을 인스턴스에서 사용할 수 있도록 하였습니다.

### MustacheMe Docker 이미지 구축

8. [8]소스 디렉터리로 이동합니다.

```
$ cd lab-1-microservices/src/MustacheMe/forklift```

9. [9]다음과 같이 현재 Dockerfile에서 Docker 이미지를 구축합니다(아래 명령줄 끝에 있는 점에 주의하세요).

```
$ docker build –t forklift .```

10. [10]첫 번째 컨테이너 이미지가 결합되고 있는 동안, 재빨리 짬을 내어 이 애플리케이션이 어떤 방식으로 구축되는지 볼 수 있습니다.

![](https://us-west-2-aws-staging.s3.amazonaws.com/awsu-bootcamp/AWS-300-RCM/v3.0/lab-1-microservices/scripts/images/DockerStructure.png)

*api-static* 폴더에는 필요한 소스 파일이 모두 들어 있습니다. *CV2*에는
수염을 배치하는 데 필요한 [OpenCV](http://opencv.org/)(오픈 소스 컴퓨터
비전) 라이브러리가 있습니다. 한편 안면 인식 파트는
[haarcascades](http://docs.opencv.org/trunk/d7/d8b/tutorial_py_face_detection.html)에
있습니다. *nginx* 폴더에는 MustacheMe의 웹 서빙 파트가 들어 있습니다.
이제 남은 것은 *process\_img*와 *static*이라는 두 폴더입니다.
process\_img 폴더에는 수염, 로고와 같은 이미지 처리에 사용되는 자산이
들어 있습니다. 이미지 처리가 끝나면 "수염이 달린" 이미지는
"processed"라는 폴더에 저장됩니다. 그리고 static 폴더에는 웹 사이트에서
활용하는 모든 미디어 및 텍스트 자산이 들어 있습니다.

### 모놀리스 컨테이너 구축 및 실행

11. [11]“forklift” MustacheMe 컨테이너를 로컬에서 실행합니다.

```
$ docker run –dp 8000:8000 forklift```

–p 는 컨테이너의 8000번 포트를 호스트상의 8000번 포트에 결합한다는
뜻입니다. –d는 Docker에게 분리 모드(Unix의 백그라운드 프로세스에 해당)로
실행되도록 명령합니다.

12. [12]브라우저에서 애플리케이션에 접속합니다. 이를 위해서는 방금 접속한 EC2
인스턴스의 DNS 이름을 복사하여 브라우저의 주소 막대에 붙여넣기만 하면
됩니다. 그 다음에 **:8000**을 끝에 추가합니다. 아래 이미지와 같이 표시될
것입니다.

![](https://us-west-2-aws-staging.s3.amazonaws.com/awsu-bootcamp/AWS-300-RCM/v3.0/lab-1-microservices/scripts/images/mustachemeapp.png)

저희가 경험한 바로는 많은 기업 VPN에서 비공용 TCP 포트를 사용하지
못하도록 막아놓고 있습니다. 따라서 8000번 포트에서 웹 프런트-엔드에
접속할 수 없는 경우, **VPN을 통해 접속하고 있기 때문에 그런 것은 아닌지
확인해야 합니다.**

13. [13]이제 재미 삼아 약간의 "수염 붙이기" 작업을 해볼 수 있습니다. 오렌지색
상자에 사진을 집어넣고 원본 사진에 수염을 익살 맞게 배치해보세요.

### 컨테이너 중지

14. [14]이 컨테이너를 종료해보겠습니다.

```
$ docker stop $(docker ps -lq)```

좋습니다. 이제 이 모놀리스를 세분화해보겠습니다.

### 로컬에서 마이크로 서비스 구축 및 실행

**개요**

이 작업에서는 Docker Compose로 컨테이너를 결합하여 컨테이너들이 서로
협력하도록 하는 방법에 대해 살펴봅니다.

**나리오**

모놀리스는 컨테이너 내부에서 실행됩니다. 그러나 이 컨테이너는 다소
다루기 불편합니다. 웹 사이트가 큰 성공을 거두어 더 많은 프런트-엔드
서버가 필요한 경우라면 어떻게 하시겠습니까? 아마 자기 얼굴에 수염을
달기보다는 자기 친구가 수염을 단 모습을 보고 싶어 하는 사람들이 더 많을
것입니다. 하지만 모놀리스로는 그 모두를 실행하고 복제해야 합니다. 개발의
관점에서는 애플리케이션에서 어느 곳이든 변경할 때마다 코드 전체를
병합하고 애플리케이션 전체를 다시 빌드한 후 이것을 테스트 환경에
제출하고, 이 모두를 배포해야 합니다. 서로 협력하면서도 분리되어 있어
상호 교체 가능한 소규모 서비스가 여러 개 있다면 이 작업이 훨씬 더 쉽고
빨라질 것입니다.

### MustacheMe 기본 이미지 구축

15. [15]소스 디렉터리로 이동합니다.

```
$ cd ~/lab-1-microservices/src/MustacheMe/MustacheMeBase/```

16. [16]다음과 같이 현재 Dockerfile에서 Docker 이미지를 구축합니다(아래 명령줄
끝에 있는 점에 주의하세요).

```
$ docker build –t mustacheme:base .```

### MustacheMe 마이크로 서비스 Docker 이미지를 구축하고 Docker Compose를 사용하여 실행

17. [17]CLI 인스턴스에 연결된 상태에서 소스 디렉터리로 이동합니다.

```
$ cd ~/lab-1-microservices/src/MustacheMe/```

18. [18]Docker Compose를 사용하여 모든 마이크로 서비스를 위한 Docker 이미지를
단번에 구축합니다. 다음 명령줄은 필요한 이미지를 모두 구축할 뿐 아니라
컨테이너를 함께 실행합니다. 자세한 내용은 docker-compose.yml을
확인하세요.

```
$ docker-compose up -d```

19. [19]이렇게 하면 애플리케이션의 내부를 들여다볼 수 있는 또 한 번의 좋은 기회를 얻게 됩니다. 전에는 모놀리스였던 것이 이제 서로 협력하는 컨테이너 3개로 이루어져 있습니다. HTTP 커뮤니케이션을 처리하고 프런트-엔드를 표시하는 MustacheMeWebServer가 있습니다. 화면 왼쪽에 보이는 정보 팁을 담당하는 MustacheMeInfo 컨테이너가 있고, 끝으로 이미지 링크를 입력으로 받아 수염이 배치된 사진을 출력으로 반환하는 MustacheMeProcessor 컨테이너가 있습니다.

20. 아래의 명령줄을 입력하여 실행되는지 봅니다.

```
$ docker-compose ps```

21. [21]브라우저를 사용하여 다시 CLI 인스턴스의 퍼블릭 DNS 이름을 탐색(:8000을
추가하는 것을 잊으면 안 됩니다)한 다음, 애플리케이션이, 비록 마이크로 서비스 조합의 지원을 받기는 하지만, 실행되는 것을 확인합니다.

22. 애플리케이션을 종료해보겠습니다.

```
$ docker-compose down```

이제 Amazon EC2 Container Service에서 이 설정 전체를 실행해볼
시간입니다!

### 마이크로 서비스 이미지를 Amazon EC2 Container Registry에 푸시

**개요**

이 작업에서는 Amazon ECR을 Docker 이미지용 리포지토리 장소로 활용하는
방법에 대해 살펴봅니다. Amazon EC2 Container Registry (ECR)는 완전
관리형 Docker 컨테이너 레지스트리로서, 개발자가 Docker 컨테이너 이미지를
손쉽게 저장, 관리 및 배포할 수 있게 해줍니다.

**시나리오**

이제 여러분은 애플리케이션이 마이크로 서비스 집합의 형태로 실행될 수
있음을 알게 되었습니다. 저장 및 공유를 위해 이 이미지를 안전한 장소로
푸시해보겠습니다.

### 콘솔을 통해 첫 번째 리포지토리를 생성하고 첫 번째 이미지를 ECR로 푸시

23. [23]브라우저에서 <https://console.aws.amazon.com/ecs/>로 이동하여 왼쪽 열에
있는 Repositories를 클릭합니다.

24. Get Started 버튼을 클릭합니다. 버튼이 보이지 않으면 Create repository
버튼을 클릭합니다.

25. 리포지토리 이름을 “microservices\_webserver”로 입력한 후 Next step
버튼을 클릭합니다.

리포지토리가 생성되면 일련의 지침이 표시됩니다. 오늘은 [ECR 자격 증명
헬퍼](https://github.com/awslabs/amazon-ecr-credential-helper)를 활용할
것이므로 이 지침은 무시해도 됩니다. Docker 자격 증명을 안전하게 유지하고
Amazon EC2 Container Registry를 사용하기 쉽게 만들어주는 것은 Docker
데몬용 네이티브 스토어입니다.

26. [26]Done을 클릭합니다.

리포지토리 URI가 필요합니다. 이것은 https:// 접두사가 없는 리포지토리
URL입니다.

27. [27]프로세서 마이크로 서비스를 태그해보겠습니다.

```
$ docker tag mustacheme_webserver \<계정 번호>.dkr.ecr.<리전>.amazonaws.com/microservices_webserver:latest```
&lt;계정 번호&gt; 및 &lt;리전&gt;이 있는 마지막 비트가 앞서 복사한 URI가
될 것입니다. 위 명령줄에서 강조 표시되어 있는 부분입니다. 해당 이미지를
푸시하기 위해 이를 다시 사용할 것입니다.

28. [28]이미지를 푸시합니다.

```
$ docker push \<계정 번호>.dkr.ecr.<리전>.amazonaws.com/microservices_webserver:latest```

### 다른 리포지토리를 생성하고 적절한 이미지를 푸시

29. [29]이제 두 번째 이미지로 넘어갑시다. 이번에는 명령줄에서
**microservices\_processor** 리포지토리를 만듭니다.

```
$ aws ecr create-repository --repository-name microservices_processor```

이 명령은 “repositoryName”, “repositoryArn” 및 “repositoryUri”가 포함된
출력을 생성합니다. URI를 복사합니다.

30. [30]프로세서 마이크로 서비스를 태그해보겠습니다.

```
$ docker tag mustacheme_processor \<계정 번호>.dkr.ecr.<리전>.amazonaws.com/microservices_processor:latest```

&lt;계정 번호&gt; 및 &lt;리전&gt;이 있는 마지막 비트가 앞서 복사한 URI가
될 것입니다. 위 명령줄에서 강조 표시되어 있는 부분입니다. 해당 이미지를
푸시하기 위해 이를 다시 사용할 것입니다.

31. [31]이제 이미지를 푸시합니다.

```
$ docker push \<계정 번호>.dkr.ecr.<리전>.amazonaws.com/microservices_processor:latest```

32. [32]방금 여러분은 웹 서버와 프로세서 마이크로 서비스를 위한 리포지토리를
생성하고 그 이미지를 태그한 후, 해당 리포지토리로 푸시하였습니다. 이제
여러분은 마지막 서비스에 대해 같은 작업을 직접 하실 수 있습니다. Docker
이미지는 microservices\_info라고 합니다. 이제 다른 서비스 이름으로 위의
세 단계를 수행하기만 하면 됩니다. 이제 여러분 혼자서도 할 수 있습니다!

### ecs-cli Compose를 사용하여 ECS에서 MustacheMe 마이크로 서비스 실행

**개요**

이 작업에서는 ecs-cli compose의 도움을 받아 ECS 클러스터에서 MustacheMe
서비스를 시작하는 방법에 대해 살펴봅니다.

*주의:* 이 작업은 선택 사항입니다.

**시나리오**

여러분은 Docker 이미지를 ECR에 업로드하였습니다. 이제는 MustacheMe
마이크로 서비스를 클러스터에 쉽게 배치할 수 있습니다. 이렇게 할 수 있는
방법은 많지만, 여러분은 **docker compose**를 사용했으므로 ECS에 상응하는
것을 사용해보겠습니다.

우리가 ecs-cli compose를 사용할 수 있도록 애써준 엔지니어는 현재 이를
작동할 수 없는 상황입니다. 그는 파일을 그대로 두고 떠나면서 "이것은
작동하지 않습니다. 이 전화를 받고 나서 10분 후에 다시
살펴보겠습니다"라고 말했습니다. 두 달 전에 있었던 일입니다. 이 YAML
형식의 파일을 수정하는 일을 도와주실 수 있습니까? 아래 지침과 함께
힌트들 드리겠습니다.

### ecs-cli compose 구성

ecs-cli는 접속한 CLI 인스턴스에 미리 설치되어 있습니다. 그러나 ecs-cli를
사용하기 전에 사용할 리전을 알려주고 기존 ECS 클러스터를 가리키도록
하여(선택 사항임) ecs-cli를 미리 구성해야 합니다. 여러분은 인스턴스가
하나인 클러스터를 구축했으므로 그것을 사용해보도록 하겠습니다. ECS
클러스터 이름이 필요할 것입니다.

33. [33]추가 실습 정보에서 ECS 클러스터 이름을 검색합니다(CLI 인스턴스 정보를
검색할 때와 마찬가지임)

34. 이제 CLI 인스턴스 터미널로 돌아가 다음과 같이 입력합니다.

```
$ ecs-cli configure --region $(aws configure get region) \--cluster <ECS 클러스터 이름>```

ecs-cli에 발생한 문제를 해결해야 하는 경우, \~/.ecs/config를 살펴봅니다.
그러나 적절한 리전 또는 클러스터 ID를 입력하지 않은 경우에만 문제가
발생합니다.

### Compose 파일 사용

35. [35]ecs-cli 디렉터리에서 **ecs-cli** 친화적인 compose 파일을 찾을 수
있습니다.

```
$ cd ~/lab-1-microservices/src/MustacheMe/ecs-cli```

36. [36]ECS CL과 함께 마이크로 서비스를 구축하는 간단한 방법은 다음과 같이
입력하는 것입니다.

```
$ ecs-cli compose up```

37. [37]다음 명령을 사용하여 현재 실행 중인 것(또는 이전 단계에서 무엇인가
실패한 경우에는 실행되고 있지 않은 것...힌트 힌트)이 무엇인지 알아낼 수
있습니다

```
$ ecs-cli ps```

**docker-compose.yml에 몇 가지 오류가 있지만**, 대체로 두 가지 부류로
나뉩니다. ECS CLI 설명서 페이지
(<https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ECS_CLI_tutorial.html#ECS_CLI_tutorial_compose_create>)가
도움이 될 수 있습니다.

…

*힌트 1*: 이미지 참조가 100% 정확하지는 않은가요?

…

다른 힌트가 필요하지는 않습니까?

*힌트 2*: 컨테이너를 서로 연결해야 합니다. 이 링크가 제대로 보입니까?

…

38. [38]시스템이 작동 중인지 어떻게 확인하십니까? 먼저 [ECS
콘솔](https://console.aws.amazon.com/ecs/home)로 이동한 후 해당
클러스터를 클릭합니다.

39. ECS Instances 탭을 클릭합니다.

40. Container Instance가 보이면 클릭합니다.

41. 이 인스턴스의 퍼블릭 DNS 레코드가 보일 것입니다. 그것을 복사합니다.

![](https://us-west-2-aws-staging.s3.amazonaws.com/awsu-bootcamp/AWS-300-RCM/v3.0/lab-1-microservices/scripts/images/ecscluster.jpg)

42. [42]이 대상을 검색할 때 URL에 :8000을 추가해야 합니다.

43. 다 되었으면 MustacheMe를 종료합니다.

```
$ ecs-cli compose down```

44. 서비스가 중단 상태로 변경되었는지 확인합니다.

```
$ ecs-cli ps```

**실습 1 마이크로 서비스 – 완료**
