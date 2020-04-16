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
					docker.build("kvalitetsit/gooioidwsrest-module", "--network testgooioidwsrest_gooioidwsrest -f Dockerfile .")
				}
			}
		}
	}
	post {
		always {

			dir('testgooioidwsrest') {
				sh 'docker-compose -f docker-compose-db.yml stop'
                                sh 'docker-compose stop'
			}
		}
	}
}

