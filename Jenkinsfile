pipeline {
	agent any
        options {
                disableConcurrentBuilds()
        }
	stages {

		stage('Clone repository') {
			steps {
				checkout scm
			}
		}

                stage('Build Docker resouce images with to be used during build') {
                        steps {
                                script {
					docker.build("build-gooioidwsrestresources/sts", "-f ./testgooioidwsrest/Dockerfile-resources-sts --no-cache ./testgooioidwsrest")
                                        docker.build("build-gooioidwsrestresources/servicea", "-f ./testgooioidwsrest/Dockerfile-resources-servicea --no-cache ./testgooioidwsrest")
                                }
                        }
                }

		stage('Make sure that the testenvironments starts from clean') {
                       steps {
                                dir('testgooioidwsrest') {
					sh 'docker-compose -f docker-compose-db.yml rm -f'
                                        sh 'docker-compose rm -f'
					sh 'docker-compose -f docker-compose-caddy.yml rm -f'
                                }
                        }
		}

		stage('Startup the testenvironment used by the integration tests') {
			steps {
				dir('testgooioidwsrest') {
					sh 'docker-compose -f docker-compose-db.yml up -d'
					sh 'sleep 2s'
					sh 'docker-compose up -d'
					sh 'sleep 3m'
				}
			}
		}
        stage('Build kit/git image') {
            steps {
               sh 'docker build -t kit/git -f Dockerfile-github . --build-arg SSH_PRIVATE_KEY="`cat /config/id_rsa`"'
            }
        }
		stage('Build Docker image (oioidwsrest module)') {
			steps {
				script {
					docker.build("kvalitetsit/gooioidwsrest-module", "--network testgooioidwsrest_gooioidwsrest -f Dockerfile .")
				}
			}
		}
                stage('Build Docker image (caddy module)') {
                        steps {
                                script {
                                        docker.build("kvalitetsit/gooioidwsrest", "-f Dockerfile-caddy .")
                                }
                        }
                }
                stage('Build Docker image (caddy templates)') {
                        steps {
                                script {
                                        docker.build("kvalitetsit/gooioidwsrest-templates", "-f Dockerfile-caddytemplates .")
                                }
                        }
                }
                stage('Build Docker resouce images for caddy modules (wsp and wsc)') {
                        steps {
                                script {
                                        docker.build("build-gooioidwsrestresources/caddy", "-f ./testgooioidwsrest/Dockerfile-resources-caddytest --no-cache ./testgooioidwsrest")
                                }
                        }
                }
                stage('Run integration tests for caddy module') {
                        steps {
                                dir('testgooioidwsrest') {
                                        sh 'docker-compose -f docker-compose-caddy.yml up -d'
                                }
                        }
                }
		stage('Tag Docker image and push to registry') {
			steps {
				script {
        				image = docker.image("kvalitetsit/gooioidwsrest")
                                        image.push("dev")

                                        if (env.TAG_NAME != null && env.TAG_NAME.startsWith("v"))
                                        {
                                                echo "Tagging version."
                                                image.push(env.TAG_NAME.substring(1))
                                                image.push("latest")
                                        }

				}
			}
		}

                stage('Tag Docker image for templates and push to registry') {
                        steps {
                                script {
                                        image = docker.image("kvalitetsit/gooioidwsrest-templates")
                                        image.push("dev")

                                        if (env.TAG_NAME != null && env.TAG_NAME.startsWith("v"))
                                        {
                                                echo "Tagging version."
                                                image.push(env.TAG_NAME.substring(1))
                                                image.push("latest")
                                        }
                                }
                        }
                }
	}
	post {
		always {

			dir('testgooioidwsrest') {
				sh 'docker-compose -f docker-compose-db.yml stop'
                                sh 'docker-compose -f docker-compose-caddy.yml stop'
                                sh 'docker-compose stop'
			}
		}
	}
}

