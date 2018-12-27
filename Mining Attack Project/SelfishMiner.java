package edu.nyu.crypto.csci3033.miners;

import java.util.ArrayList;

import edu.nyu.crypto.csci3033.blockchain.Block;
import edu.nyu.crypto.csci3033.blockchain.NetworkStatistics;

public class SelfishMiner extends BaseMiner implements Miner {
	private Block publicHead;
	boolean attack = false;
	ArrayList<Block> blocks = new ArrayList<Block>();
	private float connectivity;
	private Block privateHead;
	private int privateBranchLen = 0;

	public SelfishMiner(String id, int hashRate, int connectivity) {
		super(id, hashRate, connectivity);
	}

	@Override
	public Block currentlyMiningAt() { // secret network
		return privateHead;
	}

	@Override
	public Block currentHead() {
		return publicHead;
	}

	@Override
	public void blockMined(Block block, boolean isMinerMe) {
		int difference = (privateHead == null ? 0 : privateHead.getHeight())
				- (publicHead == null ? 0 : publicHead.getHeight());
		if (isMinerMe && connectivity > .25f) {
			privateHead = block;
			privateBranchLen++;
			if (difference == 0 && privateBranchLen == 2) { // private chain
				publicHead = privateHead;
				privateBranchLen = 0;
			}
			privateHead = publicHead;
		} else {
			if (block != null && block.getHeight() > publicHead.getHeight()) {
				publicHead = block;
				if (difference == 0) {
					privateHead = publicHead;
					privateBranchLen = 0;
				} else if (difference == 1) {
					publicHead = privateHead.getPreviousBlock();
				} else if (difference == 2) {
					publicHead = privateHead;
					privateBranchLen = 0;
				}

			}
			privateHead = publicHead;
		}
	}

	@Override
	public void initialize(Block genesis, NetworkStatistics networkStatistics) {
		this.publicHead = genesis;
		this.privateHead = genesis;
		privateBranchLen = 0;

	}

	@Override
	public void networkUpdate(NetworkStatistics statistics) {
		float hr = (float) this.getHashRate() / statistics.getTotalHashRate();
		connectivity = this.getConnectivity() / statistics.getTotalConnectivity();
		if (hr >= .25f) {
			attack = true;
		} else {
			attack = false;
		}
	}
}
