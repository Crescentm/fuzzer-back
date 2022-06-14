WORKDIR=$PWD
if [ -e $WORKDIR/bnode/bnode_pid ]; then
    kill $(cat $WORKDIR/bnode/bnode_pid)
    rm $WORKDIR/bnode/bnode_pid
    echo "stop bootnode"
fi

if [ -e $WORKDIR/node1/node1_pid ]; then
    kill $(cat $WORKDIR/node1/node1_pid)
    rm $WORKDIR/node1/node1_pid
    echo "stop node1"
fi

if [ -e $WORKDIR/node2/node2_pid ]; then
    kill $(cat $WORKDIR/node2/node2_pid)
    rm $WORKDIR/node2/node2_pid
    echo "stop node2"
fi
