podTemplate(
        containers: [containerTemplate(image: 'kvalitetsit/docker-compose:dev', name: 'docker', command: 'cat', ttyEnabled: true)],
        volumes: [hostPathVolume(hostPath: '/var/run/docker.sock', mountPath: '/var/run/docker.sock')],
        //hostNetwork: true,
) {
    node(POD_LABEL) {
        properties([disableConcurrentBuilds()])
        try {
            stage('Clone repository') {
                checkout scm
            }

            stage('Build Docker resouce images with to be used during build') {
                container('docker') {
                    docker.build("build-gooioidwsrestresources/sts", "-f ./testgooioidwsrest/Dockerfile-resources-sts --no-cache ./testgooioidwsrest")
                    docker.build("build-gooioidwsrestresources/servicea", "-f ./testgooioidwsrest/Dockerfile-resources-servicea --no-cache ./testgooioidwsrest")
                }
            }

            stage('Make sure that the testenvironments starts from clean') {
                container('docker') {
                    dir('testgooioidwsrest') {
                        sh 'docker-compose -f docker-compose-db.yml rm -f'
                        sh 'docker-compose rm -f'
                    }
                }
            }

            stage('Startup the testenvironment used by the integration tests') {
                container('docker') {
                    dir('testgooioidwsrest') {
                        docker.withRegistry('', 'dockerhub') {
                            sh 'docker-compose -f docker-compose-db.yml up -d'
                            sh 'sleep 2s'
                            sh 'docker-compose up -d'
                            sh 'sleep 3m'
                        }
                    }
                }
            }

            stage('Build Docker image (oioidwsrest module)') {
                container('docker') {
                    docker.build("kvalitetsit/gooioidwsrest-module", "--network testgooioidwsrest_gooioidwsrest -f Dockerfile .")
                }
            }
        } finally {
            container('docker') {
                stage('Clean up') {
                    dir('testgooioidwsrest') {
                        sh 'docker-compose -f docker-compose-db.yml stop'
                        sh 'docker-compose stop'
                    }
                }
            }
        }
    }
}

