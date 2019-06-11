from zardus/angr
run echo "travis_fold:start:Dapt\033[33;1mservice Dockerfile apt\033[0m" && \
    apt-get -qq update && apt-get install -qq xinetd && \
    echo "\ntravis_fold:end:Dapt\r"
# python3-pip, etc.

copy pitas.py /
# copy bins /bins

# Or, include the flag file in the repository
copy flag /bins/flag
copy service.conf /service.conf
# copy banner_fail /
# copy wrapper /wrapper

expose 5000
cmd ["/usr/sbin/xinetd", "-filelog", "-", "-dontfork", "-f", "/service.conf"]
