@Library('libpipelines@master') _

hose {
    EMAIL = 'frameworks2'
    MODULE = 'janithor'
    REPOSITORY = 'github.com/janithor'
    BUILDTOOL = 'maven'
    BUILDTOOLVERSION = '3.5.0'
    DEVTIMEOUT = 20
    RELEASETIMEOUT = 30
    DEPLOYONPRS = true

    DEV = { config ->
        doCompile(config)
        doPackage(config)
        doDeploy(config)
    }     
}
