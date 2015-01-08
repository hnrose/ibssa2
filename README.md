Scalable Subnet Administration (SSA)
===================================


SSA forms a distribution tree with up to 4 layers. At the top of
the tree is the core layer which is coresident with the OpenSM.
Next layer in the tree is the distribution layer, which fans out to
the access layer. Consumer/compute node (ACMs) are at the lowest layer
of the tree. The size of the distribution tree is dependent on
the number of compute nodes.

SSA distributes the SM database down the distribution tree to the
access nodes. The access nodes compute the SA path record ("half-world")
database for their client (compute) nodes and populate the caches
in the ACMs. "Half-world" means paths from the client (compute) node
to every other node in the IB subnet.
