WORKDIR=$PWD

# remove node1 without accounts
geth --datadir $WORKDIR/node1 removedb

# remove node2
geth --datadir $WORKDIR/node2 removedb

