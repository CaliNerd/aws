## Lab 0: Pre-Requisites

**Overview**

During this one-day boot camp, you will learn how to use Amazon Web
Services to architect, deploy, run, and manage applications constructed
from a collection of containerized micro-services. You will be
leveraging Docker to build containers and EC2 Container Service (Amazon
ECS) to deploy and run these containers. You will also learn how to
integrate other AWS services with your microservices architecture such
as Elastic Load Balancers, Cloudwatch monitoring, and a third-party
solution, HashiCorps Consul, for Service Discovery.

The bootcamp includes several hands-on exercises:

- Pre-requisites & qwikLABS setup (the guide you are now reading)

- Building and running your first container

- Constructing your microservice-enabled application

- Running microservices on Amazon ECS using the Service scheduler

- Running batch workers on Amazon ECS

- Service Discovery and Telemetry on Amazon ECS

### Prerequisites

This lab requires:

- Access to a notebook computer with Wi-Fi running Microsoft Windows, Mac OS X, or Linux (Ubuntu, SuSE, or Red Hat).

-  The qwikLABS lab environment is not accessible using an iPad or tablet device, but you can use these devices to access the student guide.

- For Microsoft Windows users: Administrator access to the computer.

- An Internet browser such as Chrome, Firefox, or IE9 (previous versions of Internet Explorer are not supported).

- An SSH client such as PuTTY.

### Start your lab

1. [1]Click the **Start Lab** button.
2. If you are using Microsoft Windows, skip to step 4. Otherwise, download the PEM file from qwikLABS.
3. OSX/Linux/Git Bash Users: You will likely have to change permissions on the downloaded PEM file for SSH to allow you to make a remote connect. The following command sets the correct permissions in OSX/Linux/Git Bash:

		chmod 600 <YOUR PEM FILE> 

4. [4]Windows Users: You will need to use the putty.exe application
(or similar) to connect to your EC2 instance using SSH. PuTTY requires
the key to be in PPK format. Download the PPK file from the qwikLABS interface.

Here are the steps to configure and connect to your instance using
PuTTY.
	<ol type = a>
	<li>Start <b>PuTTY</b> (from the Windows Start menu, choose All Programs→PuTTY→PuTTY). </li>
	<li>A dialog box opens with a Category menu on the left side. On the right side, the basic options for your PuTTY session are displayed. In the Host Name field, you will enter the public DNS name or public IP address of your instance. You can optionally prefix the DNS name or public IP address with ec2-user@ to automatically log in with the ec2-user, which you will be using today for all instances you launch.</li>
	<li>In the Category menu, under Connection, click <b>SSH</b> and then Auth. </li>
	<li>The options controlling SSH authentication are displayed. Click Browse and navigate to the PuTTY private key file you generated at the beginning of this workshop (i.e., “qwikLABS-XXXXX-XXXXX.ppk”).</li>
	<li>Click Open. An SSH session window opens and PuTTY displays a security alert asking if you trust the host you're connecting to. Click Yes.</li>
	<li>In the SSH session window, log in as ec2-user if you didn't as part of starting the SSH session. <i>Note</i>: If you specified a passphrase when you converted your private key to PuTTY's format, you must provide that passphrase when you log in to the instance.</li>
	<li>There may be messages about packages that can be applied. For the sake of the lab, you won’t worry about applying those, but in a real-world scenario you’d want to make sure you were at least applying security updates and using the latest AMIs whenever possible.</li>
	</ol>

## Lab 1: Microservices  

**Overview**

During this one-day boot camp, you will learn how to use Amazon Web
Services to architect, deploy, run, and manage applications constructed from a collection of containerized micro-services. You will be leveraging Docker to build containers and EC2 Container Service (Amazon ECS) to deploy and run these containers. You will also learn how to integrate other AWS services with your microservices architecture such as Application Load Balancers, CloudWatch monitoring, and a third-party solution for secret sharing.

The bootcamp includes several hands-on exercises:

- Pre-requisites & QwikLABS setup

- Building and running your first container

- Constructing your microservice-enabled application

- Running microservices on Amazon ECS using the Service scheduler

- Running auto-scaling services on Amazon ECS

- Service Discovery, secret sharing, and Telemetry on Amazon ECS

**Duration**

This lab should take you about **45 minutes**.

## Task 1: Retrieve the CLI instance DNS name and Connect to It

**Overview**

The CLI instance you are going to connect to is part of a CloudFormation stack. Let’s go find its name.

1. [1]From the qwikLABS lab, click **Open Console** and use the credentials provided for *awsstudent* to login to the console.
2. In the top menu bar, click **Services** > **CloudFormation**. What you see in the table are *stacks* - infrastructures that have been spun up according to a json-formattted template. Click on the line that has **CliInstanceStack** in its name.
3. In the lower pane, click on the Outputs tab.
4. Find the key named **PublicDnsName** and the value associated with it. It is the DNS you should use. In other words, the instance’s DNS is the **Value** for which the **Key** is **PublicDnsName**. Copy this somewhere (your clipboard/buffer, for example).
5. You could also find the CLI instance DNS name from within Qwiklabs, in the blue tab called “Addl. Info” on the right side of the page.
6. Change directory to where your .pem file is located.
7. SSH into the instance.

```
ssh -i <yourkey.pem> ec2-user@<your ec2 instance public dns name>
```    

## Task 2: Building and Running the Monolithic Application in a Container - Build the MustacheMe Docker Image

**Overview**

This task shows you how to create a container using a Dockerfile and how
to run and stop a single container.

**Scenario**

You are connected to the CLI instance and will build the application as it is built since the startup you are part of was incepted, except you are going to wrap it in a container. So, it is going to be a containerized monolith. Then, you will play around with the app a little bit.

In a real-life scenario, you would probably have to fetch the source code from a repository but in the interest of time we have made the latest version available to you on the instance.

8. [8]Navigate to the source directory. 

		cd lab-1-microservices/src/MustacheMe/forklift

9. [9]Build the Docker image from the present Dockerfile (notice the dot at the end of the command line below):

		docker build -t forklift .

10. [10]While your first container image is getting assembled, you can quickly take the time to look at how this application was built:

![](https://us-west-2-aws-staging.s3.amazonaws.com/awsu-bootcamp/AWS-300-RCM/v3.0/lab-1-microservices/scripts/images/DockerStructure.png)

11. [11]Within the *api-static* folder are all the source files that you need.
12. In *CV2* are the [OpenCV](http://opencv.org/) (open source computer vision) libraries that are needed for placing the mustache, while the face detection part is kept in [haarcascades](http://docs.opencv.org/trunk/d7/d8b/tutorial_py_face_detection.html). 
13. The *nginx* folder contains the web serving part of MustacheMe and you’re left with two folders: *process\_img* and *static*.
14. In the process\_img, you have the assets used for the image processing such as the moustaches and logos. After processing of images, the "moustached" images are stored there in a "processed" folder. And, static contains all the media and text assets we leverage in the website.

## Task 2: Build and run the monolith container

15. [15]Run the “forklift” MustacheMe container locally.

		docker run -dp 8000:8000 forklift

You are binding port 8000 from the container to port 8000 on the host
with –p. –d tells Docker to run in detached mode (equivalent to
background processes in Unix).

16. Connect to the application from your browser. For this, you’ll simply need to copy the DNS name for the EC2 instance you were just connected to and paste it into your browser’s address bar. Then, add **:8000** at the end. You should see something like what is provided below:

![](https://us-west-2-aws-staging.s3.amazonaws.com/awsu-bootcamp/AWS-300-RCM/v3.0/lab-1-microservices/scripts/images/mustachemeapp.png)

In our experience a lot of corporate VPNs prevent the use of non-common TCP ports. Therefore, if you cannot reach the web front-end on port 8000, **make sure that you are not connecting via VPN.**

17. [17]At this point, you should feel free to enjoy a bit of “mustaching”. Go ahead and drop a picture in the orange box and be amused as it facetiously places facial hair on the original picture.

18. Let us shutdown this container.

		docker stop $(docker ps -lq)

Good. Now, let’s get to breaking down this monolith.

## Task 3: Building and Running Microservices, Locally

**Overview**

This task shows you how to assemble containers with Docker Compose so
they can work together.

**Scenario**

The monolith runs inside a container. But, this container is rather
unwieldy. What if your website is really successful and you need more
front-end servers? Maybe there are more people willing to view their
friends with a mustache than people willing to apply a mustache, and yet with the monolith you are left with having to run it all and duplicate it all. From a development perspective, every time you make a change within the application, at any place, you need to merge all your code, rebuild the whole application and ship it to your testing environment, and deploy it all. It would be a lot easier and agile if you had multiple small services that worked together but were decoupled and interchangeable.

19. [19]Navigate to the source directory.

		cd ~/lab-1-microservices/src/MustacheMe/MustacheMeBase/

20. [20]Build the Docker image from the present Dockerfile (notice the dot at the end of the command line below):

		docker build -t mustacheme:base .

21. [21]Remain connected to the CLI instance and navigate to the source directory.

		cd ~/lab-1-microservices/src/MustacheMe/

22. [22]Build the Docker images for all microservices in one fell swoop with Docker Compose. The following is not only going to build all images required but also run the containers together. Check out
docker-compose.yml for more information.

		docker-compose up -d

23. [23]This brings us to another good opportunity to look at the innards of our application. What used to be a monolith is now made of 3 containers working with each other. There is a MustacheMeWebServer that handles the HTTP communication and displays the front-end. There is MustacheMeInfo container responsible for the info tidbits visible on the left side of the screen and finally there is the MustacheMeProcessor container that will take an image link as input and return a mustached picture as output.

24. Go ahead and see it run by typing what is given below:

		docker-compose ps

25. Once again you should use your browser to navigate to the CLI instance’s public DNS name, without forgetting to add :8000, and witness that the application is running, albeit being served by a combination of microservices.

26. Let us bring down the application.

		docker-compose down

Time for us to run this whole setup on Amazon EC2 Container Service!

## Task 4: Pushing the Microservice Images to Amazon EC2 Container Registry

**Overview**

This task shows you how to leverage Amazon ECR as the place of
repository for your Docker images. Amazon EC2 Container Registry (ECR)
is a fully-managed Docker container registry that makes it easy for
developers to store, manage, and deploy Docker container images.

**Scenario**

Now, you know the application can run as a set of microservices. Let us push these images to a safe place so they can be stored and shared.

27. [27]In the **AWS Mangement Console**, in the top menu bar, click **Services**, then click **EC2 Container Service**.

28. Click **Get started**. If you do not see one then hit **Create repository**.

29. For **repository name**, type **microservices\_webserver** as the repository name and click **Next step**.

	The repository is created and you are shown a set of instructions. You can ignore these instructions today because you are leveraging [the ECR Credential Helper](https://github.com/awslabs/amazon-ecr-credential-helper). It is a native store for the Docker daemon that keeps Docker credentials safe and makes it easier to use Amazon EC2 Container Registry.

30. [30]Click Done. Copy the **Repository URI**.

31. Let us tag the processor microservice.

		docker tag mustacheme_webserver <ACCOUNTNUMBER>.dkr.ecr.<REGION>.amazonaws.com/microservices_webserver:latest

That last bit with &lt;ACCOUNTNUMBER&gt; and &lt;REGION&gt; will be the URI you copied earlier. You are
using it again to push the image.

32. [32]Push it.

		docker push <ACCOUNTNUMBER>.dkr.ecr.<REGION>.amazonaws.com/microservices_webserver:latest

33. [33]Now, onto our second image. Create the **microservices\_processor** repo
from the command line this time:

		aws ecr create-repository --repository-name microservices_processor

	This command will generate an output that contains “repositoryName”, “repositoryArn” and “repositoryUri”. You will want to copy URI.

34. [34]Let us tag the processor microservice.

		docker tag mustacheme_processor <ACCOUNTNUMBER>.dkr.ecr.<REGION>.amazonaws.com/microservices_processor:latest 

That last bit with <ACCOUNTNUMBER> and <REGION> will be the
URI you copied earlier. You are going to use it again to push the image.

35. [35]And, push it.

		docker push <ACCOUNTNUMBER>.dkr.ecr.<REGION>.amazonaws.com/microservices_processor:latest

36. [36]You’ve just created a repo for the webserver and the processor
microservices, then tagged their images and pushed them to their
respective repos. Now, you can do the last service by yourself. The
Docker image is called microservices\_info. All you have to do is follow the above 3 steps with a different service name. You’re on your own!

## Task 5 (Optional): Running the MustacheMe Microservices on ECS with ecs-cli Compose

**Overview**

This task shows you how to bring up the MustacheMe service on your ECS
cluster with the help of ecs-cli compose.

**Scenario**

You have uploaded your Docker images to ECR. You can now easily deploy
the MustacheMe microservices on your cluster. There are many ways to do this but because you used **docker compose** before, let’s use the ECS equivalent.

Now our last engineer who tried to make ecs-cli compose work for us was not able to get it all up and running. He left the file as is, declaring “this isn’t working, gotta take this call, I’ll look into this in 10 minutes”. This happened 2 months ago. Can you help us fix this YAML-formatted file? There are hints along with the instructions below.

## Configure ecs-cli compose

ecs-cli is pre-installed on the CLI instance you are connected to. But
before you can use it, you need to configure it by telling it what
region to use and optionally pointing it to an existing ECS cluster. You happen to have stood up a one-instance cluster so let us use it. You are going to need the ECS cluster name.

37. [37]Find the ECS Cluster Name in the Additional Lab Information (just like you found the CLI instance information).

38. [38]Now, go back to your CLI instance terminal and type the following:

		ecs-cli configure --region $(aws configure get region) --cluster <ECS CLUSTER NAME>

If you ever need to troubleshoot ecs-cli, look in \~/.ecs/config but issues will only arise if you did not enter the proper region or cluster ID.

39. [39]You will find the **ecs-cli**-friendly compose file in the ecs-cli directory:

		cd ~/lab-1-microservices/src/MustacheMe/ecs-cli

40. [40]Here is how one would stand up microservices together with ECS CLI, simply by typing:

		ecs-cli compose up

41. [41]You can use the following command to find out what is running (or not running if something happened to fail in the previous step…hint hint):

		ecs-cli ps

**There are a few things wrong with the docker-compose.yml file** but
they fall into two sets. Maybe the ECS CLI documentation page will help you: <https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ECS_CLI_tutorial.html#ECS_CLI_tutorial_compose_create>

…

*Hint 1*: Maybe the image references are not 100% correct?

…

You do not need another hint, do you?

*Hint 2*: You need to link containers to each other. Do these links look
right?

…

42. [42]How do you make sure the system is working? In the **AWS Mangement Console**, in the top menu bar, click **Services**, then click **EC2 Container Service** and click on your cluster.

43. [43]Click on the ECS Instances tab.

44. Click on the Container Instance you see.

45. You will see a Public DNS record for this instance. Copy it.

![](https://us-west-2-aws-staging.s3.amazonaws.com/awsu-bootcamp/AWS-300-RCM/v3.0/lab-1-microservices/scripts/images/ecscluster.jpg)

46. [46]When browsing to this destination, make sure to add :8000 to the URL.

47. When you are done, make sure to bring MustacheMe down.

		ecs-cli compose down

48. [48]Check that the services have changed to a stopped state.

		ecs-cli ps

**Lab 1 Microservices – Complete**

