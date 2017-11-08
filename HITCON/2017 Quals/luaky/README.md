# Luaky & Very Luaky (HITCON 2017 Quals)

> by Qwaz

This problem requires us to write a lua script that plays rock-scissors-paper game. There are three computer AIs: slime, alpaca, and nozomi. We won a game if we won more than 90,000 rounds out of 100,000 rounds. Each game should be done in 1 second. We can get the previous choice of the computer as an argument to the function.

## Luaky

We can get the flag of Luaky if we won a game with slime and won ten consecutive game with nozomi or alpaca. The routine of slime is simple: `choice = (choice + 1) % 3`. We won the game if `(ai + 1)%3 == opponent`, so we can won every game with slime by mimicking its previous move.

Alpaca is harder than a slime. It generates a random seed, and do `seed = prev_ai + seed - 0x61c88647` and `chioce = seed % 3`. At first, it is tempting to handle the calculation as `seed = prev_ai + seed - 1`, since 0x61c88647 is 1 modular 3. However, we should consider integer overflow. If `prev_ai + seed` is less than the magic value, 0x100000000 is added to the seed and the prediction fails.

We overcome this limitation by adaptively change our guess value. Usually, two 0x61c88647 fits in one integer range: `0x61c88647 * 2 = 0xc3910c8e`. When this assumption fails, it means the actual seed was smaller than our guess, so that `remainder + 0xc3910c8e > 0x100000000`. When this event happens, we simply reset our guessed seed to 0x420000000.

## Very Luaky

Nozomi generates a random seed each game and perform `seed = 48271 * seed % 0x7FFFFFFF` every round. We only see `choice = seed % 3`. The modular 0x7FFFFFFF makes the reverse calculation harder, because the problem only gives us a modular of modular.

We could narrow our search area by comparing `seed % 3` to `(coeff * seed % 0x7FFFFFFF) % 3`. Modularization can be changed to subtraction: `(coeff * seed - k * 0x7FFFFFFF) % 3`. We are only interested in cases where `k % 3` is our desired value. Then, we can find a ranges of seed that satisfies the simulation result. We can choose multiple coefficients and combine their range to reduce the searching area effectively.

We should also implement computer AI detection for very luaky task. This can be done simply by assuming that the computer is slime or alpaca and count the winning ratio. If winning ratio is high enough, we classify the computer AI as an instance of that type.

The final lua code is as follows. We should minify our code before sending it to the server.

```lua
STAGE = 100000
INT = 0x100000000
M = 0x7FFFFFFF

result = 0
cnt = 0

function slime (x)
	return x % 3
end

AL_last = 0
AL_magic = 0x61C88647
AL_guess = 0
function alpaca (x)
	if AL_last and (result+1)%3 ~= x then
		AL_guess = INT*2 - (0x42000000 + AL_magic*2)
	end
	if AL_guess > AL_magic then
		AL_guess = AL_guess - AL_magic
		AL_last = 1
		return (x+result+1) % 3
	else
		AL_guess = INT + AL_guess - AL_magic
		AL_last = 0
		return (x+result+2) % 3
	end
end

NZ_C = 48271
NZ_save = {}
NZ_size = 7
NZ_stage = 8000
NZ_now = 0
NZ_x = {}
NZ_coeff = {48271, 665722, 560989, 353062, 248479, 232463, 64536}
NZ_lvl = {1, 282, 2048, 2718, 3840, 4763, 7426}
function check_seed (x)
	NZ_now = x
	for i = 2, NZ_stage-1 do
		if NZ_now % 3 ~= NZ_save[i] then
			return false
		end
		NZ_now = NZ_C * NZ_now % M
	end
	return true
end
function nozomi (x)
	remain = cnt % STAGE
	if remain == 1001 then
		NZ_save = {}
		return 0
	elseif remain < 1001+NZ_stage then
		table.insert(NZ_save, x)
		return 0
	elseif remain == 1001+NZ_stage then
		table.insert(NZ_save, x)
		for k = 1, NZ_size do
			diff = (NZ_save[2+NZ_lvl[k]] - NZ_coeff[k]*NZ_save[2]) % 3
			if diff == 0 then
				NZ_x[k] = 0
			elseif diff == 2 then
				NZ_x[k] = 1
			else
				NZ_x[k] = 2
			end
		end
		seed = 0
		while seed == 0 do
			while true do
				bmin = 0
				smax = M
				for k = 1, NZ_size do
					x = NZ_x[k]
					tmin = (M*x + NZ_coeff[k]-1) // NZ_coeff[k]
					tmax = (M*(x+1)) // NZ_coeff[k]
					bmin = math.max(bmin, tmin)
					smax = math.min(smax, tmax)
				end
				if bmin <= smax then
					break
				end
				for k = 1, NZ_size do
					tmax = (M*(NZ_x[k]+1)) // NZ_coeff[k]
					while tmax < bmin do
						NZ_x[k] = NZ_x[k] + 3
						tmax = (M*(NZ_x[k]+1)) // NZ_coeff[k]
					end
				end
			end
			bmin = bmin//3*3 + NZ_save[2]
			for seed_cand = bmin, smax, 3 do
				now = check_seed(seed_cand)
				if check_seed(seed_cand) then
					seed = seed_cand
					print('seed: ' .. seed)
					break
				end
			end
			for k = 1, NZ_size do
				tmax = (M*(NZ_x[k]+1)) // NZ_coeff[k]
				if tmax <= smax then
					NZ_x[k] = NZ_x[k] + 3
				end
			end
		end
	end
	NZ_now = NZ_now * NZ_C % M
	return (NZ_now+2) % 3
end

sl_win = 0
al_win = 0
function play (x)
	cnt = cnt+1
	remain = cnt % STAGE
	if remain == 1 then
		sl_win = 0
		al_win = 0
	end
	if remain <= 500 then
		if (result+1) % 3 == x then
			sl_win = sl_win + 1
		end
		result = slime(x)
	elseif remain <= 1000 then
		if (result+1) % 3 == x then
			al_win = al_win + 1
		end
		result = alpaca(x)
	else
		if sl_win > 400 then
			result = slime(x)
		elseif al_win > 400 then
			result = alpaca(x)
		else
			result = nozomi(x)
		end
	end
	return result
end
-- EOF

```

