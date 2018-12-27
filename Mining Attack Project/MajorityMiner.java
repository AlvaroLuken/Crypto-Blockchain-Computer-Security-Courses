package edu.nyu.crypto.csci3033.miners;

import java.util.ArrayList;

import edu.nyu.crypto.csci3033.blockchain.Block;
import edu.nyu.crypto.csci3033.blockchain.NetworkStatistics;

public class MajorityMiner extends BaseMiner implements Miner {
	private Block head;
	private Block old;
	private Block old2;
	private Block old3;
	private Block old4;
	private Block old5;
	private Block old6;
	boolean attack = false;
	ArrayList<Block> blocks = new ArrayList<Block>();

	public MajorityMiner(String id, int hashRate, int connectivity) {
		super(id, hashRate, connectivity);
	}

	@Override
	public Block currentlyMiningAt() {
		return head;
	}

	@Override
	public Block currentHead() {
		if (attack) {
			return old6;
		} else {
			return head;
		}
	}

	@Override
	public void blockMined(Block block, boolean isMinerMe) {
		if (isMinerMe) {
			if (block.getHeight() > head.getHeight()) {
				this.old6 = old5;
				this.old5 = old4;
				this.old4 = old3;
				this.old3 = old2;
				this.old2 = old;
				this.old = head;
				this.head = block;
			}
		} else {
			if (head == null) {
				this.old6 = old5;
				this.old5 = old4;
				this.old4 = old3;
				this.old3 = old2;
				this.old2 = old;
				this.old = head;
				this.head = block;
			} else if (block != null && block.getHeight() > head.getHeight()) {
				this.old6 = old5;
				this.old5 = old4;
				this.old4 = old3;
				this.old3 = old2;
				this.old2 = old;
				this.old = head;

				this.head = block;
			}
		}
	}

	@Override
	public void initialize(Block genesis, NetworkStatistics networkStatistics) {
		this.old6 = genesis;
		this.old5 = genesis;
		this.old4 = genesis;
		this.old3 = genesis;
		this.old2 = genesis;
		this.head = genesis;
		this.old = genesis;

	}

	@Override
	public void networkUpdate(NetworkStatistics statistics) {
		float hr = (float) this.getHashRate() / statistics.getTotalHashRate();
		if (hr >= .51f) {
			attack = true;
		} else {
			attack = false;

		}
	}
}
