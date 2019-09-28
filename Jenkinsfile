pipeline {
	agent any

	stages {

		stage('Clone repository') {
			steps {
				checkout scm
			}
		}

		stage('Startup the testenvironment used by the integration tests') {
			steps {
				dir('testgooioidwsrest') {
					sh 'docker-compose -f docker-compose-db.yml up -d'
					sh 'sleep 2000'
					sh 'docker-compose up -d'
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

	}
	post {
		always {

			dir('testenv') {
				sh 'docker-compose -f docker-compose-db.yml stop'
                                sh 'docker-compose stop'
				sh 'docker-compose -f docker-compose-db.yml rm -f'
                                sh 'docker-compose rm -f'
			}
		}
	}
}
