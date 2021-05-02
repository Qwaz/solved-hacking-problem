function sort (arr)
    for i=1,#arr do
        for j=i+1,#arr do
            if arr[j] < arr[i] then
                local t = arr[j]
                arr[j] = arr[i]
                arr[i] = t
            end
        end
    end
    return arr
end

function encode(arr, num)
    if #arr == 1 then
        return arr
    end

    local pi = 1
    for i=1,#arr-1 do
        pi = pi * i
    end

    local result = {}
    local remove_index = (num // pi) + 1
    table.insert(result, arr[remove_index])

    local sub = {}
    for i=1,#arr do
        if i ~= remove_index then
            table.insert(sub, arr[i])
        end
    end

    local child = encode(sub, num % pi)
    for i=1,#child do
        table.insert(result, child[i])
    end

    return result
end

function decode(arr)
    if #arr == 1 then
        return 0
    end

    local pi = 1
    for i=1,#arr-1 do
        pi = pi * i
    end

    local result = 0
    for i=2,#arr do
        if arr[i] < arr[1] then
            result = result + pi
        end
    end

    local sub = {}
    for i=2,#arr do
        table.insert(sub, arr[i])
    end
    result = result + decode(sub)

    return result
end

function Alice1 (hand)
    hand = sort(hand)
    
    xor_sum = 0
    for i=1,8 do
        xor_sum = xor_sum ~ (hand[i] % 8)
    end
    idx_to_discard = xor_sum + 1

    num = hand[idx_to_discard]

    discarded = {}
    for i=1,8 do
        if i ~= idx_to_discard then
            table.insert(discarded, hand[i])
        end
    end

    discarded_xor_sum = 0
    for i=1,7 do
        discarded_xor_sum = discarded_xor_sum ~ (discarded[i] % 8)
    end

    cnt = 0
    for idx=0,7 do
        if idx == 0 then
            low = 1
        else
            low = discarded[idx] + 1
        end
        if idx == 7 then
            high = 40000
        else
            high = discarded[idx + 1] - 1
        end

        mod_8 = idx ~ discarded_xor_sum

        while (low % 8) ~= mod_8 do
            low = low + 1
        end
        while (high % 8) ~= mod_8 do
            high = high - 1
        end

        if low <= high then
            in_range_count = ((high - low) // 8) + 1
        else
            in_range_count = 0
        end

        if low <= num and num <= high then
            cnt = cnt + ((num - low) // 8)
            return encode(discarded, cnt)
        else
            cnt = cnt + in_range_count
        end
    end

    return nil
end

function Bob1 (hand)
    xor_sum = 0
    for i=1,7 do
        xor_sum = xor_sum ~ (hand[i] % 8)
    end

    remain_cnt = decode(hand)

    hand = sort(hand)

    for idx=0,7 do
        if idx == 0 then
            low = 1
        else
            low = hand[idx] + 1
        end
        if idx == 7 then
            high = 40000
        else
            high = hand[idx + 1] - 1
        end

        mod_8 = idx ~ xor_sum

        while (low % 8) ~= mod_8 do
            low = low + 1
        end
        while (high % 8) ~= mod_8 do
            high = high - 1
        end

        if low <= high then
            in_range_count = ((high - low) // 8) + 1
        else
            in_range_count = 0
        end

        if remain_cnt < in_range_count then
            return low + remain_cnt * 8
        else
            remain_cnt = remain_cnt - in_range_count
        end
    end

    return -1
end

function Alice2 (arr)
    to_zero = {}
    for i=1,96 do
        if arr[i] == 2 then
            index = (i % 96) + 1
            while arr[index] ~= 1 do
                index = (index % 96) + 1
            end
            arr[index] = 0
            table.insert(to_zero, index)
        end
    end
    return to_zero
end

function Bob2 (arr)
    to_two = {}
    for i=1,96 do
        if arr[i] == 0 then
            index = i - 1
            if index == 0 then index = 96 end
            while arr[index] ~= 1 do
                index = index - 1
                if index == 0 then index = 96 end
            end
            arr[index] = 2
            table.insert(to_two, index)
        end
    end
    return to_two
end
