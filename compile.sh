# get the location of this script file, relative to the current shell working directory
BASEDIR=$(dirname "$0")
# get the absolute, path, docker does not allow mounting volumes by a relative path
hostpath="$( cd "$BASEDIR" && pwd )"
rm -rf $BASEDIR/build
mkdir -p $BASEDIR/build
docker run --rm --name cdt --volume $hostpath:/project \
  -w /project ghcr.io/wombat-tech/antelope.cdt:v4.0.0 /bin/bash -c \
  "mkdir -p build && cd build && cmake -DCMAKE_TOOLCHAIN_FILE=/usr/opt/cdt/4.0.0/lib/cmake/cdt/CDTWasmToolchain.cmake .. && make"
  # Need to set the toolchain here for cross compilation
