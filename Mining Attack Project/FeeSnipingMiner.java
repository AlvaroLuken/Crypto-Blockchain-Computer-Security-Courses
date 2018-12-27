package edu.nyu.crypto.csci3033.miners;

import java.util.ArrayList;

import edu.nyu.crypto.csci3033.blockchain.Block;
import edu.nyu.crypto.csci3033.blockchain.NetworkStatistics;

public class FeeSnipingMiner extends BaseMiner implements Miner {
	private Block head;
	private Block old;
	boolean attack = false;
	private float hashpower;
	private float connectivity;
	private ArrayList<Block> history = new ArrayList<Block>();

	public FeeSnipingMiner(String id, int hashRate, int connectivity) {
		super(id, hashRate, connectivity);
	}

	@Override
	public Block currentlyMiningAt() {

		return head;
	}

	@Override
	public Block currentHead() {

		return head;
	}

	private double computeAverageBlockReward() {
		int sum = 0;
		double average;
		for (int i = 0; i < history.size(); i++) {
			sum += history.get(i).getBlockValue();
		}
		if (history.size() == 0) {
			return average = 1;
		}
		System.out.println("here!!!!!!");

		average = sum / history.size();

		return average;
	}

	@Override
	public void blockMined(Block block, boolean isMinerMe) {
		if (isMinerMe) {
			if (block.getHeight() > head.getHeight()) {
				this.head = block;
				history.add(block); // stop
				attack = false;
			}
		} else {
			if (head == null) {
				System.out.println("HIIII");
				this.head = block;
			} else if (block != null && block.getHeight() > head.getHeight()) {
				// System.out.println(block.getHeight() - head.getHeight());
				this.head = block;
				// computeAverageBlockReward()
				if (block.getBlockValue() >= 6) {
					if (hashpower > .25f) {
						this.head = this.head.getPreviousBlock();

						// this.head = head.getPreviousBlock();
						attack = true; // commence attack
					}

				}
				// add third condition: continue attack
				//

			}
		}
	}

	@Override
	public void initialize(Block genesis, NetworkStatistics networkStatistics) {
		this.head = genesis;
	}

	@Override
	public void networkUpdate(NetworkStatistics statistics) {
		float hr = (float) this.getHashRate() / statistics.getTotalHashRate();

		connectivity = this.getConnectivity() / statistics.getTotalConnectivity();

		hashpower = hr;

	}
}
