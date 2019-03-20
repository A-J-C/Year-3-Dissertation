#!/bin/bash
#SBATCH -p par6.q
#SBATCH -N 1
#SBATCH --cpus-per-task=1

module purge
module load python/3.6.8
module load slurm/current

pip3 install --user -r requirements.txt
