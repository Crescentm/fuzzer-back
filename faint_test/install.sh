WORKDIR=$PWD

echo "using geth: $(which geth)"

# if [ -e $WORKDIR/bnode/bnode_pid || -e $WORKDIR/node1/node1_pid || -e $WORKDIR/node2/node2_pid ]; then
if [ -e $WORKDIR/bnode/bnode_pid ] || [ -e $WORKDIR/node1/node1_pid ] || [ -e $WORKDIR/node2/node2_pid ]; then
    echo "There is a running testnet, you need to remove it before start a new one"
    exit 0
fi

# initialize node1 and node2 with faint.json
if [ ! -d $WORKDIR/node1/geth ]; then
    geth --datadir ./node1 init faint.json
    echo "initialize node1"
fi

if [ ! -d $WORKDIR/node2/geth ]; then
    geth --datadir ./node2 init faint.json
    echo "initialize node2"
fi

# generate bootnode key and start bootnode
cd $WORKDIR/bnode
if [ ! -e bnode.key ]; then
    bootnode --genkey bnode.key
fi

bootnode --nodekey bnode.key &> bnode_log.txt &
echo "$!" > bnode_pid

until [ $bnode_enode ]; do
    bnode_enode="$(head -n1 bnode_log.txt)"
    # echo "$bnode_enode"
done

echo "start bootnode at $bnode_enode"

cd $WORKDIR
# get account
account1="$(cat accounts.txt | head -n1)"
account2="$(cat accounts.txt | tail -n1)"
echo "account1: $account1"
echo "account2: $account2"

# start node1
cd $WORKDIR/node1
cmd="geth --datadir=$PWD \
--bootnodes $bnode_enode \
--syncmode full \
--port 10001 \
--mine \
--miner.gasprice 0 \
--miner.gastarget 470000000000 \
--http \
--http.addr 0.0.0.0 \
--http.port 8001 \
--http.api admin,eth,miner,net,txpool,personal,web3 \
--http.corsdomain http://localhost:8001 \
--allow-insecure-unlock \
--unlock $account1 \
--password password.txt &> node1_log.txt &"
echo "start node1: $cmd"
eval $cmd
echo "$!" > node1_pid

# start node2
cd $WORKDIR/node2
cmd="geth --datadir=$PWD \
--bootnodes $bnode_enode \
--syncmode full \
--port 10002 \
--mine \
--miner.gasprice 0 \
--miner.gastarget 470000000000 \
--http \
--http.addr 0.0.0.0 \
--http.port 8002 \
--http.api admin,eth,miner,net,txpool,personal,web3 \
--http.corsdomain http://localhost:8002 \
--allow-insecure-unlock \
--unlock $account2 \
--password password.txt &> node2_log.txt &"
echo "start node2: $cmd"
eval $cmd
echo "$!" > node2_pid

