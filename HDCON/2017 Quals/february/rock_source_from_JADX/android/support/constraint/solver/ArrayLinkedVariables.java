package android.support.constraint.solver;

import android.support.constraint.solver.SolverVariable.Type;
import java.util.Arrays;

public class ArrayLinkedVariables {
    private static final boolean DEBUG = false;
    private static final int NONE = -1;
    private int ROW_SIZE = 8;
    private SolverVariable candidate = null;
    int currentSize = 0;
    private int[] mArrayIndices = new int[this.ROW_SIZE];
    private int[] mArrayNextIndices = new int[this.ROW_SIZE];
    private float[] mArrayValues = new float[this.ROW_SIZE];
    private final Cache mCache;
    private boolean mDidFillOnce = false;
    private int mHead = -1;
    private int mLast = -1;
    private final ArrayRow mRow;

    ArrayLinkedVariables(ArrayRow arrayRow, Cache cache) {
        this.mRow = arrayRow;
        this.mCache = cache;
    }

    public final void put(SolverVariable variable, float value) {
        if (value == 0.0f) {
            remove(variable);
        } else if (this.mHead == -1) {
            this.mHead = 0;
            this.mArrayValues[this.mHead] = value;
            this.mArrayIndices[this.mHead] = variable.id;
            this.mArrayNextIndices[this.mHead] = -1;
            this.currentSize++;
            if (!this.mDidFillOnce) {
                this.mLast++;
            }
        } else {
            int current = this.mHead;
            int previous = -1;
            int counter = 0;
            while (current != -1 && counter < this.currentSize) {
                if (this.mArrayIndices[current] == variable.id) {
                    this.mArrayValues[current] = value;
                    return;
                }
                if (this.mArrayIndices[current] < variable.id) {
                    previous = current;
                }
                current = this.mArrayNextIndices[current];
                counter++;
            }
            int availableIndice = this.mLast + 1;
            if (this.mDidFillOnce) {
                if (this.mArrayIndices[this.mLast] == -1) {
                    availableIndice = this.mLast;
                } else {
                    availableIndice = this.mArrayIndices.length;
                }
            }
            if (availableIndice >= this.mArrayIndices.length && this.currentSize < this.mArrayIndices.length) {
                for (int i = 0; i < this.mArrayIndices.length; i++) {
                    if (this.mArrayIndices[i] == -1) {
                        availableIndice = i;
                        break;
                    }
                }
            }
            if (availableIndice >= this.mArrayIndices.length) {
                availableIndice = this.mArrayIndices.length;
                this.ROW_SIZE *= 2;
                this.mDidFillOnce = false;
                this.mLast = availableIndice - 1;
                this.mArrayValues = Arrays.copyOf(this.mArrayValues, this.ROW_SIZE);
                this.mArrayIndices = Arrays.copyOf(this.mArrayIndices, this.ROW_SIZE);
                this.mArrayNextIndices = Arrays.copyOf(this.mArrayNextIndices, this.ROW_SIZE);
            }
            this.mArrayIndices[availableIndice] = variable.id;
            this.mArrayValues[availableIndice] = value;
            if (previous != -1) {
                this.mArrayNextIndices[availableIndice] = this.mArrayNextIndices[previous];
                this.mArrayNextIndices[previous] = availableIndice;
            } else {
                this.mArrayNextIndices[availableIndice] = this.mHead;
                this.mHead = availableIndice;
            }
            this.currentSize++;
            if (!this.mDidFillOnce) {
                this.mLast++;
            }
            if (this.currentSize >= this.mArrayIndices.length) {
                this.mDidFillOnce = true;
            }
        }
    }

    public final void add(SolverVariable variable, float value) {
        if (value != 0.0f) {
            if (this.mHead == -1) {
                this.mHead = 0;
                this.mArrayValues[this.mHead] = value;
                this.mArrayIndices[this.mHead] = variable.id;
                this.mArrayNextIndices[this.mHead] = -1;
                this.currentSize++;
                if (!this.mDidFillOnce) {
                    this.mLast++;
                    return;
                }
                return;
            }
            int current = this.mHead;
            int previous = -1;
            int counter = 0;
            while (current != -1 && counter < this.currentSize) {
                int idx = this.mArrayIndices[current];
                if (idx == variable.id) {
                    float[] fArr = this.mArrayValues;
                    fArr[current] = fArr[current] + value;
                    if (this.mArrayValues[current] == 0.0f) {
                        if (current == this.mHead) {
                            this.mHead = this.mArrayNextIndices[current];
                        } else {
                            this.mArrayNextIndices[previous] = this.mArrayNextIndices[current];
                        }
                        this.mCache.mIndexedVariables[idx].removeClientEquation(this.mRow);
                        if (this.mDidFillOnce) {
                            this.mLast = current;
                        }
                        this.currentSize--;
                        return;
                    }
                    return;
                }
                if (this.mArrayIndices[current] < variable.id) {
                    previous = current;
                }
                current = this.mArrayNextIndices[current];
                counter++;
            }
            int availableIndice = this.mLast + 1;
            if (this.mDidFillOnce) {
                if (this.mArrayIndices[this.mLast] == -1) {
                    availableIndice = this.mLast;
                } else {
                    availableIndice = this.mArrayIndices.length;
                }
            }
            if (availableIndice >= this.mArrayIndices.length && this.currentSize < this.mArrayIndices.length) {
                for (int i = 0; i < this.mArrayIndices.length; i++) {
                    if (this.mArrayIndices[i] == -1) {
                        availableIndice = i;
                        break;
                    }
                }
            }
            if (availableIndice >= this.mArrayIndices.length) {
                availableIndice = this.mArrayIndices.length;
                this.ROW_SIZE *= 2;
                this.mDidFillOnce = false;
                this.mLast = availableIndice - 1;
                this.mArrayValues = Arrays.copyOf(this.mArrayValues, this.ROW_SIZE);
                this.mArrayIndices = Arrays.copyOf(this.mArrayIndices, this.ROW_SIZE);
                this.mArrayNextIndices = Arrays.copyOf(this.mArrayNextIndices, this.ROW_SIZE);
            }
            this.mArrayIndices[availableIndice] = variable.id;
            this.mArrayValues[availableIndice] = value;
            if (previous != -1) {
                this.mArrayNextIndices[availableIndice] = this.mArrayNextIndices[previous];
                this.mArrayNextIndices[previous] = availableIndice;
            } else {
                this.mArrayNextIndices[availableIndice] = this.mHead;
                this.mHead = availableIndice;
            }
            this.currentSize++;
            if (!this.mDidFillOnce) {
                this.mLast++;
            }
            if (this.mLast >= this.mArrayIndices.length) {
                this.mDidFillOnce = true;
                this.mLast = this.mArrayIndices.length - 1;
            }
        }
    }

    public final float remove(SolverVariable variable) {
        if (this.candidate == variable) {
            this.candidate = null;
        }
        if (this.mHead == -1) {
            return 0.0f;
        }
        int current = this.mHead;
        int previous = -1;
        int counter = 0;
        while (current != -1 && counter < this.currentSize) {
            int idx = this.mArrayIndices[current];
            if (idx == variable.id) {
                if (current == this.mHead) {
                    this.mHead = this.mArrayNextIndices[current];
                } else {
                    this.mArrayNextIndices[previous] = this.mArrayNextIndices[current];
                }
                this.mCache.mIndexedVariables[idx].removeClientEquation(this.mRow);
                this.currentSize--;
                this.mArrayIndices[current] = -1;
                if (this.mDidFillOnce) {
                    this.mLast = current;
                }
                return this.mArrayValues[current];
            }
            previous = current;
            current = this.mArrayNextIndices[current];
            counter++;
        }
        return 0.0f;
    }

    public final void clear() {
        this.mHead = -1;
        this.mLast = -1;
        this.mDidFillOnce = false;
        this.currentSize = 0;
    }

    final boolean containsKey(SolverVariable variable) {
        if (this.mHead == -1) {
            return false;
        }
        int current = this.mHead;
        int counter = 0;
        while (current != -1 && counter < this.currentSize) {
            if (this.mArrayIndices[current] == variable.id) {
                return true;
            }
            current = this.mArrayNextIndices[current];
            counter++;
        }
        return false;
    }

    boolean hasAtLeastOnePositiveVariable() {
        int current = this.mHead;
        int counter = 0;
        while (current != -1 && counter < this.currentSize) {
            if (this.mArrayValues[current] > 0.0f) {
                return true;
            }
            current = this.mArrayNextIndices[current];
            counter++;
        }
        return false;
    }

    void invert() {
        int current = this.mHead;
        int counter = 0;
        while (current != -1 && counter < this.currentSize) {
            float[] fArr = this.mArrayValues;
            fArr[current] = fArr[current] * -1.0f;
            current = this.mArrayNextIndices[current];
            counter++;
        }
    }

    void divideByAmount(float amount) {
        int current = this.mHead;
        int counter = 0;
        while (current != -1 && counter < this.currentSize) {
            float[] fArr = this.mArrayValues;
            fArr[current] = fArr[current] / amount;
            current = this.mArrayNextIndices[current];
            counter++;
        }
    }

    void updateClientEquations(ArrayRow row) {
        int current = this.mHead;
        int counter = 0;
        while (current != -1 && counter < this.currentSize) {
            this.mCache.mIndexedVariables[this.mArrayIndices[current]].addClientEquation(row);
            current = this.mArrayNextIndices[current];
            counter++;
        }
    }

    SolverVariable pickPivotCandidate() {
        SolverVariable restrictedCandidate = null;
        SolverVariable unrestrictedCandidate = null;
        int current = this.mHead;
        int counter = 0;
        while (current != -1 && counter < this.currentSize) {
            float amount = this.mArrayValues[current];
            if (amount < 0.0f) {
                if (amount > (-981668463)) {
                    this.mArrayValues[current] = 0.0f;
                    amount = 0.0f;
                }
            } else if (amount < 0.001f) {
                this.mArrayValues[current] = 0.0f;
                amount = 0.0f;
            }
            if (amount != 0.0f) {
                SolverVariable variable = this.mCache.mIndexedVariables[this.mArrayIndices[current]];
                if (variable.mType == Type.UNRESTRICTED) {
                    if (amount < 0.0f) {
                        return variable;
                    }
                    if (unrestrictedCandidate == null) {
                        unrestrictedCandidate = variable;
                    }
                } else if (amount < 0.0f && (restrictedCandidate == null || variable.strength < restrictedCandidate.strength)) {
                    restrictedCandidate = variable;
                }
            }
            current = this.mArrayNextIndices[current];
            counter++;
        }
        if (unrestrictedCandidate != null) {
            return unrestrictedCandidate;
        }
        return restrictedCandidate;
    }

    void updateFromRow(ArrayRow self, ArrayRow definition) {
        int current = this.mHead;
        int counter = 0;
        while (current != -1 && counter < this.currentSize) {
            if (this.mArrayIndices[current] == definition.variable.id) {
                float value = this.mArrayValues[current];
                remove(definition.variable);
                ArrayLinkedVariables definitionVariables = definition.variables;
                int definitionCurrent = definitionVariables.mHead;
                int definitionCounter = 0;
                while (definitionCurrent != -1 && definitionCounter < definitionVariables.currentSize) {
                    add(this.mCache.mIndexedVariables[definitionVariables.mArrayIndices[definitionCurrent]], definitionVariables.mArrayValues[definitionCurrent] * value);
                    definitionCurrent = definitionVariables.mArrayNextIndices[definitionCurrent];
                    definitionCounter++;
                }
                self.constantValue += definition.constantValue * value;
                definition.variable.removeClientEquation(self);
                current = this.mHead;
                counter = 0;
            } else {
                current = this.mArrayNextIndices[current];
                counter++;
            }
        }
    }

    void updateFromSystem(ArrayRow self, ArrayRow[] rows) {
        int current = this.mHead;
        int counter = 0;
        while (current != -1 && counter < this.currentSize) {
            SolverVariable variable = this.mCache.mIndexedVariables[this.mArrayIndices[current]];
            if (variable.definitionId != -1) {
                float value = this.mArrayValues[current];
                remove(variable);
                ArrayRow definition = rows[variable.definitionId];
                if (!definition.isSimpleDefinition) {
                    ArrayLinkedVariables definitionVariables = definition.variables;
                    int definitionCurrent = definitionVariables.mHead;
                    int definitionCounter = 0;
                    while (definitionCurrent != -1 && definitionCounter < definitionVariables.currentSize) {
                        add(this.mCache.mIndexedVariables[definitionVariables.mArrayIndices[definitionCurrent]], definitionVariables.mArrayValues[definitionCurrent] * value);
                        definitionCurrent = definitionVariables.mArrayNextIndices[definitionCurrent];
                        definitionCounter++;
                    }
                }
                self.constantValue += definition.constantValue * value;
                definition.variable.removeClientEquation(self);
                current = this.mHead;
                counter = 0;
            } else {
                current = this.mArrayNextIndices[current];
                counter++;
            }
        }
    }

    SolverVariable getPivotCandidate() {
        if (this.candidate != null) {
            return this.candidate;
        }
        int current = this.mHead;
        int counter = 0;
        SolverVariable pivot = null;
        while (current != -1 && counter < this.currentSize) {
            if (this.mArrayValues[current] < 0.0f) {
                SolverVariable v = this.mCache.mIndexedVariables[this.mArrayIndices[current]];
                if (pivot == null || pivot.strength < v.strength) {
                    pivot = v;
                }
            }
            current = this.mArrayNextIndices[current];
            counter++;
        }
        return pivot;
    }

    final SolverVariable getVariable(int index) {
        int current = this.mHead;
        int counter = 0;
        while (current != -1 && counter < this.currentSize) {
            if (counter == index) {
                return this.mCache.mIndexedVariables[this.mArrayIndices[current]];
            }
            current = this.mArrayNextIndices[current];
            counter++;
        }
        return null;
    }

    final float getVariableValue(int index) {
        int current = this.mHead;
        int counter = 0;
        while (current != -1 && counter < this.currentSize) {
            if (counter == index) {
                return this.mArrayValues[current];
            }
            current = this.mArrayNextIndices[current];
            counter++;
        }
        return 0.0f;
    }

    public final float get(SolverVariable v) {
        int current = this.mHead;
        int counter = 0;
        while (current != -1 && counter < this.currentSize) {
            if (this.mArrayIndices[current] == v.id) {
                return this.mArrayValues[current];
            }
            current = this.mArrayNextIndices[current];
            counter++;
        }
        return 0.0f;
    }

    int sizeInBytes() {
        return (0 + ((this.mArrayIndices.length * 4) * 3)) + 36;
    }

    public void display() {
        int count = this.currentSize;
        System.out.print("{ ");
        for (int i = 0; i < count; i++) {
            SolverVariable v = getVariable(i);
            if (v != null) {
                System.out.print(v + " = " + getVariableValue(i) + " ");
            }
        }
        System.out.println(" }");
    }

    public String toString() {
        String result = "";
        int current = this.mHead;
        int counter = 0;
        while (current != -1 && counter < this.currentSize) {
            result = ((result + " -> ") + this.mArrayValues[current] + " : ") + this.mCache.mIndexedVariables[this.mArrayIndices[current]];
            current = this.mArrayNextIndices[current];
            counter++;
        }
        return result;
    }
}
