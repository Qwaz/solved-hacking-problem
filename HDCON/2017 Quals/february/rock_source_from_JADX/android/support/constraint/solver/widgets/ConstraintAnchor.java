package android.support.constraint.solver.widgets;

import android.support.constraint.solver.Cache;
import android.support.constraint.solver.SolverVariable;
import java.util.ArrayList;
import java.util.HashSet;

public class ConstraintAnchor {
    private static final boolean ALLOW_BINARY = false;
    public static final int ANY_GROUP = Integer.MAX_VALUE;
    public static final int APPLY_GROUP_RESULTS = -2;
    public static final int AUTO_CONSTRAINT_CREATOR = 2;
    public static final int SCOUT_CREATOR = 1;
    private static final int UNSET_GONE_MARGIN = -1;
    public static final int USER_CREATOR = 0;
    public static final boolean USE_CENTER_ANCHOR = false;
    private int mConnectionCreator = 0;
    private ConnectionType mConnectionType = ConnectionType.RELAXED;
    int mGoneMargin = -1;
    int mGroup = ANY_GROUP;
    public int mMargin = 0;
    final ConstraintWidget mOwner;
    SolverVariable mSolverVariable;
    private Strength mStrength = Strength.NONE;
    ConstraintAnchor mTarget;
    final Type mType;

    public enum ConnectionType {
        RELAXED,
        STRICT
    }

    public enum Strength {
        NONE,
        STRONG,
        WEAK
    }

    public enum Type {
        NONE,
        LEFT,
        TOP,
        RIGHT,
        BOTTOM,
        BASELINE,
        CENTER,
        CENTER_X,
        CENTER_Y
    }

    public ConstraintAnchor(ConstraintWidget owner, Type type) {
        this.mOwner = owner;
        this.mType = type;
    }

    public SolverVariable getSolverVariable() {
        return this.mSolverVariable;
    }

    public void resetSolverVariable(Cache cache) {
        if (this.mSolverVariable == null) {
            this.mSolverVariable = new SolverVariable(android.support.constraint.solver.SolverVariable.Type.UNRESTRICTED);
        } else {
            this.mSolverVariable.reset();
        }
    }

    public void setGroup(int group) {
        this.mGroup = group;
    }

    public int getGroup() {
        return this.mGroup;
    }

    public ConstraintWidget getOwner() {
        return this.mOwner;
    }

    public Type getType() {
        return this.mType;
    }

    public int getMargin() {
        if (this.mOwner.getVisibility() == 8) {
            return 0;
        }
        if (this.mGoneMargin <= -1 || this.mTarget == null || this.mTarget.mOwner.getVisibility() != 8) {
            return this.mMargin;
        }
        return this.mGoneMargin;
    }

    public Strength getStrength() {
        return this.mStrength;
    }

    public ConstraintAnchor getTarget() {
        return this.mTarget;
    }

    public ConnectionType getConnectionType() {
        return this.mConnectionType;
    }

    public void setConnectionType(ConnectionType type) {
        this.mConnectionType = type;
    }

    public int getConnectionCreator() {
        return this.mConnectionCreator;
    }

    public void setConnectionCreator(int creator) {
        this.mConnectionCreator = creator;
    }

    public void reset() {
        this.mTarget = null;
        this.mMargin = 0;
        this.mGoneMargin = -1;
        this.mStrength = Strength.STRONG;
        this.mConnectionCreator = 0;
        this.mConnectionType = ConnectionType.RELAXED;
    }

    public boolean connect(ConstraintAnchor toAnchor, int margin, Strength strength, int creator) {
        return connect(toAnchor, margin, -1, strength, creator, false);
    }

    public boolean connect(ConstraintAnchor toAnchor, int margin, int goneMargin, Strength strength, int creator, boolean forceConnection) {
        if (toAnchor == null) {
            this.mTarget = null;
            this.mMargin = 0;
            this.mGoneMargin = -1;
            this.mStrength = Strength.NONE;
            this.mConnectionCreator = 2;
            return true;
        } else if (!forceConnection && !isValidConnection(toAnchor)) {
            return false;
        } else {
            this.mTarget = toAnchor;
            if (margin > 0) {
                this.mMargin = margin;
            } else {
                this.mMargin = 0;
            }
            this.mGoneMargin = goneMargin;
            this.mStrength = strength;
            this.mConnectionCreator = creator;
            return true;
        }
    }

    public boolean connect(ConstraintAnchor toAnchor, int margin, int creator) {
        return connect(toAnchor, margin, -1, Strength.STRONG, creator, false);
    }

    public boolean connect(ConstraintAnchor toAnchor, int margin) {
        return connect(toAnchor, margin, -1, Strength.STRONG, 0, false);
    }

    public boolean isConnected() {
        return this.mTarget != null;
    }

    public boolean isValidConnection(ConstraintAnchor anchor) {
        boolean z = true;
        if (anchor == null) {
            return false;
        }
        Type target = anchor.getType();
        if (target != this.mType) {
            boolean isCompatible;
            switch (this.mType) {
                case CENTER:
                    if (target == Type.BASELINE || target == Type.CENTER_X || target == Type.CENTER_Y) {
                        z = false;
                    }
                    return z;
                case LEFT:
                case RIGHT:
                    if (target == Type.LEFT || target == Type.RIGHT) {
                        isCompatible = true;
                    } else {
                        isCompatible = false;
                    }
                    if (anchor.getOwner() instanceof Guideline) {
                        if (isCompatible || target == Type.CENTER_X) {
                            isCompatible = true;
                        } else {
                            isCompatible = false;
                        }
                    }
                    return isCompatible;
                case TOP:
                case BOTTOM:
                    if (target == Type.TOP || target == Type.BOTTOM) {
                        isCompatible = true;
                    } else {
                        isCompatible = false;
                    }
                    if (anchor.getOwner() instanceof Guideline) {
                        if (isCompatible || target == Type.CENTER_Y) {
                            isCompatible = true;
                        } else {
                            isCompatible = false;
                        }
                    }
                    return isCompatible;
                default:
                    return false;
            }
        } else if (this.mType == Type.CENTER) {
            return false;
        } else {
            if (this.mType != Type.BASELINE || (anchor.getOwner().hasBaseline() && getOwner().hasBaseline())) {
                return true;
            }
            return false;
        }
    }

    public boolean isSideAnchor() {
        switch (this.mType) {
            case LEFT:
            case RIGHT:
            case TOP:
            case BOTTOM:
                return true;
            default:
                return false;
        }
    }

    public boolean isSimilarDimensionConnection(ConstraintAnchor anchor) {
        boolean z = true;
        Type target = anchor.getType();
        if (target == this.mType) {
            return true;
        }
        switch (this.mType) {
            case CENTER:
                if (target == Type.BASELINE) {
                    z = false;
                }
                return z;
            case LEFT:
            case RIGHT:
            case CENTER_X:
                if (target == Type.LEFT || target == Type.RIGHT || target == Type.CENTER_X) {
                    return true;
                }
                return false;
            case TOP:
            case BOTTOM:
            case CENTER_Y:
            case BASELINE:
                if (target == Type.TOP || target == Type.BOTTOM || target == Type.CENTER_Y || target == Type.BASELINE) {
                    return true;
                }
                return false;
            default:
                return false;
        }
    }

    public void setStrength(Strength strength) {
        if (isConnected()) {
            this.mStrength = strength;
        }
    }

    public void setMargin(int margin) {
        if (isConnected()) {
            this.mMargin = margin;
        }
    }

    public void setGoneMargin(int margin) {
        if (isConnected()) {
            this.mGoneMargin = margin;
        }
    }

    public boolean isVerticalAnchor() {
        switch (this.mType) {
            case CENTER:
            case LEFT:
            case RIGHT:
            case CENTER_X:
                return false;
            default:
                return true;
        }
    }

    public String toString() {
        return this.mOwner.getDebugName() + ":" + this.mType.toString() + (this.mTarget != null ? " connected to " + this.mTarget.toString(new HashSet()) : "");
    }

    private String toString(HashSet<ConstraintAnchor> visited) {
        if (!visited.add(this)) {
            return "<-";
        }
        return this.mOwner.getDebugName() + ":" + this.mType.toString() + (this.mTarget != null ? " connected to " + this.mTarget.toString(visited) : "");
    }

    public int getSnapPriorityLevel() {
        switch (this.mType) {
            case CENTER:
                return 3;
            case LEFT:
            case RIGHT:
            case CENTER_Y:
                return 1;
            case TOP:
                return 0;
            case BOTTOM:
                return 0;
            case CENTER_X:
                return 0;
            case BASELINE:
                return 2;
            default:
                return 0;
        }
    }

    public int getPriorityLevel() {
        switch (this.mType) {
            case CENTER:
                return 2;
            case LEFT:
                return 2;
            case RIGHT:
                return 2;
            case TOP:
                return 2;
            case BOTTOM:
                return 2;
            case BASELINE:
                return 1;
            default:
                return 0;
        }
    }

    public boolean isSnapCompatibleWith(ConstraintAnchor anchor) {
        if (this.mType == Type.CENTER) {
            return false;
        }
        if (this.mType == anchor.getType()) {
            return true;
        }
        switch (this.mType) {
            case LEFT:
                switch (anchor.getType()) {
                    case RIGHT:
                        return true;
                    case CENTER_X:
                        return true;
                    default:
                        return false;
                }
            case RIGHT:
                switch (anchor.getType()) {
                    case LEFT:
                        return true;
                    case CENTER_X:
                        return true;
                    default:
                        return false;
                }
            case TOP:
                switch (anchor.getType()) {
                    case BOTTOM:
                        return true;
                    case CENTER_Y:
                        return true;
                    default:
                        return false;
                }
            case BOTTOM:
                switch (anchor.getType()) {
                    case TOP:
                        return true;
                    case CENTER_Y:
                        return true;
                    default:
                        return false;
                }
            case CENTER_X:
                switch (anchor.getType()) {
                    case LEFT:
                        return true;
                    case RIGHT:
                        return true;
                    default:
                        return false;
                }
            case CENTER_Y:
                switch (anchor.getType()) {
                    case TOP:
                        return true;
                    case BOTTOM:
                        return true;
                    default:
                        return false;
                }
            default:
                return false;
        }
    }

    public boolean isConnectionAllowed(ConstraintWidget target, ConstraintAnchor anchor) {
        return isConnectionAllowed(target);
    }

    public boolean isConnectionAllowed(ConstraintWidget target) {
        if (isConnectionToMe(target, new HashSet())) {
            return false;
        }
        ConstraintWidget parent = getOwner().getParent();
        if (parent == target) {
            return true;
        }
        if (target.getParent() == parent) {
            return true;
        }
        return false;
    }

    private boolean isConnectionToMe(ConstraintWidget target, HashSet<ConstraintWidget> checked) {
        if (checked.contains(target)) {
            return false;
        }
        checked.add(target);
        if (target == getOwner()) {
            return true;
        }
        ArrayList<ConstraintAnchor> targetAnchors = target.getAnchors();
        int targetAnchorsSize = targetAnchors.size();
        for (int i = 0; i < targetAnchorsSize; i++) {
            ConstraintAnchor anchor = (ConstraintAnchor) targetAnchors.get(i);
            if (anchor.isSimilarDimensionConnection(this) && anchor.isConnected() && isConnectionToMe(anchor.getTarget().getOwner(), checked)) {
                return true;
            }
        }
        return false;
    }

    public final ConstraintAnchor getOpposite() {
        switch (this.mType) {
            case LEFT:
                return this.mOwner.mRight;
            case RIGHT:
                return this.mOwner.mLeft;
            case TOP:
                return this.mOwner.mBottom;
            case BOTTOM:
                return this.mOwner.mTop;
            default:
                return null;
        }
    }
}
