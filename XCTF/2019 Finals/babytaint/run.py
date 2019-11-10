import os
print "Please input your one line JavaScript skimmer: "
skimmer = raw_input()
with open("/tmp/skimmer.js", "w") as f:
	f.write(skimmer)
os.system("node jalangi2/src/js/commands/jalangi.js --inlineIID --inlineSource --analysis jalangi2/src/js/sample_analyses/ChainedAnalyses.js --analysis Chall.js /tmp/skimmer.js")	