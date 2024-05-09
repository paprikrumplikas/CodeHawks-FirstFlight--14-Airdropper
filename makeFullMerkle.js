const { StandardMerkleTree } = require("@openzeppelin/merkle-tree")
const fs = require("fs")

/*//////////////////////////////////////////////////////////////
                             INPUTS
//////////////////////////////////////////////////////////////*/
const amount = (25 * 1e6).toString(); // Fixed the amount to correctly match the 25 tokens in smallest unit

const values = [
    ["0x20F41376c713072937eb02Be70ee1eD0D639966C", amount],
    ["0x277D26a45Add5775F21256159F089769892CEa5B", amount],
    ["0x0c8Ca207e27a1a8224D1b602bf856479b03319e7", amount],
    ["0xf6dBa02C01AF48Cf926579F77C9f874Ca640D91D", amount]
]

/*//////////////////////////////////////////////////////////////
                            PROCESS
//////////////////////////////////////////////////////////////*/
const tree = StandardMerkleTree.of(values, ["address", "uint256"])

console.log('Merkle Root:', tree.root)

// Generating and printing proofs for all addresses
for (const [i, v] of tree.entries()) {
    const proof = tree.getProof(i);
    console.log(`Proof for address: ${v[0]} with amount: ${v[1]}:\n`, proof);
}

// Saving the complete tree to a file
fs.writeFileSync("fullTree.json", JSON.stringify(tree.dump()));
