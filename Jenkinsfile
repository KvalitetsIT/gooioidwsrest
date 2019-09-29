pipeline {
	agent any

	stages {

		stage('Clone repository') {
			steps {
				checkout scm
			}
		}

                stage('Build Docker resouce images with to be used during build') {
                        steps {
                                script {
					docker.build("build-gooioidwsrestresources/sts", "-f ./testgooioidwsrest/Dockerfile-resources-sts ./testgooioidwsrest")
                                        docker.build("build-gooioidwsrestresources/servicea", "-f ./testgooioidwsrest/Dockerfile-resources-servicea ./testgooioidwsrest")
                                        docker.build("build-gooioidwsrestresources/wsc", "-f ./testgooioidwsrest/Dockerfile-resources-wsc ./testgooioidwsrest")
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
                                        docker.build("kvalitetsit/caddy-gooioidwsrest", "-f Dockerfile_caddy .")
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
	}
	post {
		always {

			dir('testgooioidwsrest') {
				sh 'docker-compose -f docker-compose-db.yml stop'
                                sh 'docker-compose -f docker-compose-wsc.yml stop'
                                sh 'docker-compose stop'
				sh 'docker-compose -f docker-compose-db.yml rm -f'
                                sh 'docker-compose -f docker-compose-wsc.yml rm -f'
                                sh 'docker-compose rm -f'
			}
		}
	}
}
