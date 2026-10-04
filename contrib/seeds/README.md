# Seeds

Utility to generate the seeds.txt list that is compiled into the client
(see [src/chainparamsseeds.h](/src/chainparamsseeds.h) and other utilities in [contrib/seeds](/contrib/seeds)).

Be sure to update `PATTERN_AGENT` in `makeseeds.py` to include the current version,
and remove old versions as necessary (at a minimum when SeedsServiceFlags()
changes its default return value, as those are the services which seeds are added
to addrman with).

Update `MIN_BLOCKS` in  `makeseeds.py` and the `-m`/`--minblocks` arguments below, as needed.

`makeseeds.py` judges uptime over 30 days by default. Pass `-u 7` while the
network is younger than 30 days, since no node that joined at a hardfork can
meet a 30-day threshold until a month after it.

The seeds compiled into the release are created from several DNS seeds and
asmap community AS map data. Run the following commands
from the `/contrib/seeds` directory:

```
curl https://luke.dashjr.org/programs/bitcoin/files/charts/seeds.txt > seeds_luke.txt
curl https://haf.ovh/seed.txt > seeds_haf.txt
curl https://bitcoin.sipa.be/seeds.txt.gz | gzip -dc > seeds_sipa.txt
curl https://21.ninja/seeds.txt.gz | gzip -dc > seeds_ninja.txt
curl https://mainnet.achownodes.xyz/seeds.txt.gz | gzip -dc > seeds_achow.txt
curl https://lionthunderfingers.github.io/Bitcoin-Node-census/seeds.txt > seeds_lion.txt
curl https://signet.achownodes.xyz/seeds.txt.gz | gzip -dc > seeds_signet.txt
curl https://testnet.achownodes.xyz/seeds.txt.gz | gzip -dc > seeds_test.txt
curl https://testnet4.achownodes.xyz/seeds.txt.gz | gzip -dc > seeds_testnet4.txt
curl https://raw.githubusercontent.com/asmap/asmap-data/main/latest_asmap.dat > asmap-filled.dat
python3 makeseeds.py -a asmap-filled.dat -s seeds_luke.txt seeds_haf.txt seeds_sipa.txt seeds_ninja.txt seeds_achow.txt seeds_lion.txt > nodes_main.txt
python3 makeseeds.py -a asmap-filled.dat -s seeds_signet.txt -m 237800 > nodes_signet.txt
python3 makeseeds.py -a asmap-filled.dat -s seeds_test.txt > nodes_test.txt
python3 makeseeds.py -a asmap-filled.dat -s seeds_testnet4.txt -m 72600 > nodes_testnet4.txt
python3 generate-seeds.py . > ../../src/chainparamsseeds.h
```

`-s` takes one or more source files and parses each separately before combining, rather than requiring them pre-concatenated in the shell — a source missing a trailing newline used to merge silently into the next file's first line when `cat`/`>>`'d together (producing a corrupt record, or worse, a crash with a misleading error far from the real cause). Downloading each source to its own file sidesteps that failure mode entirely.
