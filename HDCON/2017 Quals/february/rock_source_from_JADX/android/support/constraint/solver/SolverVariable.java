package android.support.constraint.solver;

import java.util.Arrays;

public class SolverVariable {
    private static final boolean INTERNAL_DEBUG = false;
    static final int MAX_STRENGTH = 6;
    public static final int STRENGTH_EQUALITY = 5;
    public static final int STRENGTH_HIGH = 3;
    public static final int STRENGTH_HIGHEST = 4;
    public static final int STRENGTH_LOW = 1;
    public static final int STRENGTH_MEDIUM = 2;
    public static final int STRENGTH_NONE = 0;
    private static int uniqueId = 1;
    public float computedValue;
    int definitionId;
    public int id;
    ArrayRow[] mClientEquations;
    int mClientEquationsCount;
    private String mName;
    Type mType;
    public int strength;
    float[] strengthVector;

    public enum Type {
        UNRESTRICTED,
        CONSTANT,
        SLACK,
        ERROR,
        UNKNOWN
    }

    private static String getUniqueName(Type type) {
        uniqueId++;
        switch (type) {
            case UNRESTRICTED:
                return "U" + uniqueId;
            case CONSTANT:
                return "C" + uniqueId;
            case SLACK:
                return "S" + uniqueId;
            case ERROR:
                return "e" + uniqueId;
            default:
                return "V" + uniqueId;
        }
    }

    public SolverVariable(String name, Type type) {
        this.id = -1;
        this.definitionId = -1;
        this.strength = 0;
        this.strengthVector = new float[6];
        this.mClientEquations = new ArrayRow[8];
        this.mClientEquationsCount = 0;
        this.mName = name;
        this.mType = type;
    }

    public SolverVariable(Type type) {
        this.id = -1;
        this.definitionId = -1;
        this.strength = 0;
        this.strengthVector = new float[6];
        this.mClientEquations = new ArrayRow[8];
        this.mClientEquationsCount = 0;
        this.mType = type;
    }

    void clearStrengths() {
        for (int i = 0; i < 6; i++) {
            this.strengthVector[i] = 0.0f;
        }
    }

    String strengthsToString() {
        String representation = this + "[";
        for (int j = 0; j < this.strengthVector.length; j++) {
            representation = representation + this.strengthVector[j];
            if (j < this.strengthVector.length - 1) {
                representation = representation + ", ";
            } else {
                representation = representation + "] ";
            }
        }
        return representation;
    }

    void addClientEquation(ArrayRow equation) {
        int i = 0;
        while (i < this.mClientEquationsCount) {
            if (this.mClientEquations[i] != equation) {
                i++;
            } else {
                return;
            }
        }
        if (this.mClientEquationsCount >= this.mClientEquations.length) {
            this.mClientEquations = (ArrayRow[]) Arrays.copyOf(this.mClientEquations, this.mClientEquations.length * 2);
        }
        this.mClientEquations[this.mClientEquationsCount] = equation;
        this.mClientEquationsCount++;
    }

    void removeClientEquation(ArrayRow equation) {
        for (int i = 0; i < this.mClientEquationsCount; i++) {
            if (this.mClientEquations[i] == equation) {
                for (int j = 0; j < (this.mClientEquationsCount - i) - 1; j++) {
                    this.mClientEquations[i + j] = this.mClientEquations[(i + j) + 1];
                }
                this.mClientEquationsCount--;
                return;
            }
        }
    }

    public void reset() {
        this.mName = null;
        this.mType = Type.UNKNOWN;
        this.strength = 0;
        this.id = -1;
        this.definitionId = -1;
        this.computedValue = 0.0f;
        this.mClientEquationsCount = 0;
    }

    public String getName() {
        return this.mName;
    }

    public void setName(String name) {
        this.mName = name;
    }

    public void setType(Type type) {
        this.mType = type;
    }

    public String toString() {
        return "" + this.mName;
    }
}
