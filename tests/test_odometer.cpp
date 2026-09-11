#include <iostream>
#include <cassert>
#include <vector>

// Simulating the Odometer extracted from BruteForceEngine
class Odometer {
    std::vector<size_t> state;
    std::vector<size_t> w_sizes;
    size_t num_unknowns;

public:
    Odometer(const std::vector<size_t>& sizes) : w_sizes(sizes) {
        num_unknowns = sizes.size();
        state.resize(num_unknowns, 0);
    }

    bool advance() {
        if (num_unknowns == 0) return false;
        int i = static_cast<int>(num_unknowns) - 1;
        while (true) {
            size_t next_val = state[i] + 1;
            if (next_val < w_sizes[i]) {
                state[i] = next_val;
                break;
            }
            state[i] = 0;
            i--;
            if (i < 0) return false;
        }
        return true;
    }

    const std::vector<size_t>& get_state() const { return state; }
};

void test_odometer() {
    std::cout << "[TDD] Testing Odometer Combinatorics...\n";
    Odometer odo({2, 3});
    
    // Initial state: 0, 0
    assert(odo.get_state()[0] == 0 && odo.get_state()[1] == 0);
    
    int count = 1;
    while (odo.advance()) {
        count++;
    }
    
    // Total combinations should be 2 * 3 = 6
    assert(count == 6);
    std::cout << "  -> Odometer 2x3 test passed (6 combinations).\n";
}

int main() {
    std::cout << "Running Odometer TDD Suite...\n";
    test_odometer();
    std::cout << "All tests passed!\n";
    return 0;
}
