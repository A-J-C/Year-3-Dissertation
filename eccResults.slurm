#!/bin/bash
#SBATCH -p seq7.q
#SBATCH -N 1
#SBATCH --cpus-per-task=1
#SBATCH --begin=2019-03-22T18:00:00

module purge
module load python/3.6.8
module load slurm/current

pip3 install --user -r requirements.txt
