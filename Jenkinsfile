pipeline {
	agent any

	stages {

		def scmInfo

		stage('Clone repository') {
			steps {
				scmInfo = checkout scm
			}
		}

                stage('Build Docker resouce images with to be used during build') {
                        steps {
                                script {
					docker.build("build-gooioidwsrestresources/sts", "-f ./testgooioidwsrest/Dockerfile-resources-sts --no-cache ./testgooioidwsrest")
                                        docker.build("build-gooioidwsrestresources/servicea", "-f ./testgooioidwsrest/Dockerfile-resources-servicea --no-cache ./testgooioidwsrest")
                                        docker.build("build-gooioidwsrestresources/wsc", "-f ./testgooioidwsrest/Dockerfile-resources-wsc --no-cache ./testgooioidwsrest")
                                }
                        }
                }

		stage('Make sure that the testenvironments starts from clean') {
                       steps {
                                dir('testgooioidwsrest') {
					sh 'docker-compose -f docker-compose-db.yml rm -f'
                                        sh 'docker-compose rm -f'
					sh 'docker-compose -f docker-compose-wsc.yml rm -f'
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

		stage('Build Docker image (oioidwsrest module)') {
			steps {
				script {
					docker.build("kvalitetsit/gooioidwsrest", "--network testgooioidwsrest_gooioidwsrest -f Dockerfile .")
				}
			}
		}
                stage('Build Docker image (caddy module)') {
                        steps {
                                script {
                                        docker.build("kvalitetsit/caddy-gooioidwsrest", "-f Dockerfile-caddy .")
                                }
                        }
                }
                stage('Run integration tests for caddy module (wsc)') {
                        steps {
                                dir('testgooioidwsrest') {
                                        sh 'docker-compose -f docker-compose-wsc.yml up -d'
                                }
                        }
                }

		stage('Tag Docker image and push to registry') {
			steps {
				script {
					docker.withRegistry('https://kitdocker.kvalitetsit.dk/') {
						docker.image("kvalitetsit/caddy-gooioidwsrest").push("${scmInfo.GIT_COMMIT}")
					}
				}
			}
		}

	}
	post {
		always {

			dir('testgooioidwsrest') {
				sh 'docker-compose -f docker-compose-db.yml stop'
                                sh 'docker-compose -f docker-compose-wsc.yml stop'
                                sh 'docker-compose stop'
			}
		}
	}
}
