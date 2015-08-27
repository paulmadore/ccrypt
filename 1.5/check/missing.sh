#! /bin/sh

# provide (dumb) replacements for missing functions

# first, because the "which" command on Solaris is totally useless,
# we need to implement our own. This code is adapted from autoconf.

my_which () {
    if [ "$#" -ne 1 ]; then
	echo "my_which: wrong number of arguments" > /dev/stderr
	return 255
    fi
    cmd=$1
    IFS="${IFS=   }"; save_ifs="$IFS"; IFS=":"
    path="$PATH"
    for dir in $path; do
	test -z "$dir" && dir=.
	if test -f $dir/$cmd; then
	    echo $dir/$cmd
	    IFS="$save_ifs"
	    return 0
	fi
    done
    IFS="$save_ifs"
    return 1
}

# "mktemp" replacement: note that this creates the same filename each time. 
# Thus, when creating more than one tempfile, must give different templates.

DUMMY=`my_which mktemp`
if [ -z "$DUMMY" ]; then
    mktemp () {
	echo $*
    }
fi

	