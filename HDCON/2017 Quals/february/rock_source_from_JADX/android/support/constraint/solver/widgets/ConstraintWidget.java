package android.support.constraint.solver.widgets;

import android.support.constraint.solver.ArrayRow;
import android.support.constraint.solver.Cache;
import android.support.constraint.solver.LinearSystem;
import android.support.constraint.solver.SolverVariable;
import android.support.constraint.solver.widgets.ConstraintAnchor.ConnectionType;
import android.support.constraint.solver.widgets.ConstraintAnchor.Strength;
import android.support.constraint.solver.widgets.ConstraintAnchor.Type;
import java.util.ArrayList;

public class ConstraintWidget {
    private static final boolean AUTOTAG_CENTER = false;
    public static final int CHAIN_PACKED = 2;
    public static final int CHAIN_SPREAD = 0;
    public static final int CHAIN_SPREAD_INSIDE = 1;
    public static float DEFAULT_BIAS = 0.5f;
    protected static final int DIRECT = 2;
    public static final int GONE = 8;
    public static final int HORIZONTAL = 0;
    public static final int INVISIBLE = 4;
    public static final int MATCH_CONSTRAINT_SPREAD = 0;
    public static final int MATCH_CONSTRAINT_WRAP = 1;
    protected static final int SOLVER = 1;
    public static final int UNKNOWN = -1;
    public static final int VERTICAL = 1;
    public static final int VISIBLE = 0;
    protected ArrayList<ConstraintAnchor> mAnchors;
    ConstraintAnchor mBaseline;
    int mBaselineDistance;
    ConstraintAnchor mBottom;
    boolean mBottomHasCentered;
    ConstraintAnchor mCenter;
    ConstraintAnchor mCenterX;
    ConstraintAnchor mCenterY;
    private Object mCompanionWidget;
    private int mContainerItemSkip;
    private String mDebugName;
    protected float mDimensionRatio;
    protected int mDimensionRatioSide;
    int mDistToBottom;
    int mDistToLeft;
    int mDistToRight;
    int mDistToTop;
    private int mDrawHeight;
    private int mDrawWidth;
    private int mDrawX;
    private int mDrawY;
    int mHeight;
    float mHorizontalBiasPercent;
    boolean mHorizontalChainFixedPosition;
    int mHorizontalChainStyle;
    DimensionBehaviour mHorizontalDimensionBehaviour;
    ConstraintWidget mHorizontalNextWidget;
    public int mHorizontalResolution;
    float mHorizontalWeight;
    boolean mHorizontalWrapVisited;
    ConstraintAnchor mLeft;
    boolean mLeftHasCentered;
    int mMatchConstraintDefaultHeight;
    int mMatchConstraintDefaultWidth;
    int mMatchConstraintMaxHeight;
    int mMatchConstraintMaxWidth;
    int mMatchConstraintMinHeight;
    int mMatchConstraintMinWidth;
    protected int mMinHeight;
    protected int mMinWidth;
    protected int mOffsetX;
    protected int mOffsetY;
    ConstraintWidget mParent;
    ConstraintAnchor mRight;
    boolean mRightHasCentered;
    private int mSolverBottom;
    private int mSolverLeft;
    private int mSolverRight;
    private int mSolverTop;
    ConstraintAnchor mTop;
    boolean mTopHasCentered;
    private String mType;
    float mVerticalBiasPercent;
    boolean mVerticalChainFixedPosition;
    int mVerticalChainStyle;
    DimensionBehaviour mVerticalDimensionBehaviour;
    ConstraintWidget mVerticalNextWidget;
    public int mVerticalResolution;
    float mVerticalWeight;
    boolean mVerticalWrapVisited;
    private int mVisibility;
    int mWidth;
    private int mWrapHeight;
    private int mWrapWidth;
    protected int mX;
    protected int mY;

    public enum ContentAlignment {
        BEGIN,
        MIDDLE,
        END,
        TOP,
        VERTICAL_MIDDLE,
        BOTTOM,
        LEFT,
        RIGHT
    }

    public enum DimensionBehaviour {
        FIXED,
        WRAP_CONTENT,
        MATCH_CONSTRAINT,
        MATCH_PARENT
    }

    public void reset() {
        this.mLeft.reset();
        this.mTop.reset();
        this.mRight.reset();
        this.mBottom.reset();
        this.mBaseline.reset();
        this.mCenterX.reset();
        this.mCenterY.reset();
        this.mCenter.reset();
        this.mParent = null;
        this.mWidth = 0;
        this.mHeight = 0;
        this.mDimensionRatio = 0.0f;
        this.mDimensionRatioSide = -1;
        this.mX = 0;
        this.mY = 0;
        this.mDrawX = 0;
        this.mDrawY = 0;
        this.mDrawWidth = 0;
        this.mDrawHeight = 0;
        this.mOffsetX = 0;
        this.mOffsetY = 0;
        this.mBaselineDistance = 0;
        this.mMinWidth = 0;
        this.mMinHeight = 0;
        this.mWrapWidth = 0;
        this.mWrapHeight = 0;
        this.mHorizontalBiasPercent = DEFAULT_BIAS;
        this.mVerticalBiasPercent = DEFAULT_BIAS;
        this.mHorizontalDimensionBehaviour = DimensionBehaviour.FIXED;
        this.mVerticalDimensionBehaviour = DimensionBehaviour.FIXED;
        this.mCompanionWidget = null;
        this.mContainerItemSkip = 0;
        this.mVisibility = 0;
        this.mDebugName = null;
        this.mType = null;
        this.mHorizontalWrapVisited = false;
        this.mVerticalWrapVisited = false;
        this.mHorizontalChainStyle = 0;
        this.mVerticalChainStyle = 0;
        this.mHorizontalChainFixedPosition = false;
        this.mVerticalChainFixedPosition = false;
        this.mHorizontalWeight = 0.0f;
        this.mVerticalWeight = 0.0f;
        this.mHorizontalResolution = -1;
        this.mVerticalResolution = -1;
    }

    public ConstraintWidget() {
        this.mHorizontalResolution = -1;
        this.mVerticalResolution = -1;
        this.mMatchConstraintDefaultWidth = 0;
        this.mMatchConstraintDefaultHeight = 0;
        this.mMatchConstraintMinWidth = 0;
        this.mMatchConstraintMaxWidth = 0;
        this.mMatchConstraintMinHeight = 0;
        this.mMatchConstraintMaxHeight = 0;
        this.mLeft = new ConstraintAnchor(this, Type.LEFT);
        this.mTop = new ConstraintAnchor(this, Type.TOP);
        this.mRight = new ConstraintAnchor(this, Type.RIGHT);
        this.mBottom = new ConstraintAnchor(this, Type.BOTTOM);
        this.mBaseline = new ConstraintAnchor(this, Type.BASELINE);
        this.mCenterX = new ConstraintAnchor(this, Type.CENTER_X);
        this.mCenterY = new ConstraintAnchor(this, Type.CENTER_Y);
        this.mCenter = new ConstraintAnchor(this, Type.CENTER);
        this.mAnchors = new ArrayList();
        this.mParent = null;
        this.mWidth = 0;
        this.mHeight = 0;
        this.mDimensionRatio = 0.0f;
        this.mDimensionRatioSide = -1;
        this.mSolverLeft = 0;
        this.mSolverTop = 0;
        this.mSolverRight = 0;
        this.mSolverBottom = 0;
        this.mX = 0;
        this.mY = 0;
        this.mDrawX = 0;
        this.mDrawY = 0;
        this.mDrawWidth = 0;
        this.mDrawHeight = 0;
        this.mOffsetX = 0;
        this.mOffsetY = 0;
        this.mBaselineDistance = 0;
        this.mHorizontalBiasPercent = DEFAULT_BIAS;
        this.mVerticalBiasPercent = DEFAULT_BIAS;
        this.mHorizontalDimensionBehaviour = DimensionBehaviour.FIXED;
        this.mVerticalDimensionBehaviour = DimensionBehaviour.FIXED;
        this.mContainerItemSkip = 0;
        this.mVisibility = 0;
        this.mDebugName = null;
        this.mType = null;
        this.mHorizontalChainStyle = 0;
        this.mVerticalChainStyle = 0;
        this.mHorizontalWeight = 0.0f;
        this.mVerticalWeight = 0.0f;
        this.mHorizontalNextWidget = null;
        this.mVerticalNextWidget = null;
        addAnchors();
    }

    public ConstraintWidget(int x, int y, int width, int height) {
        this.mHorizontalResolution = -1;
        this.mVerticalResolution = -1;
        this.mMatchConstraintDefaultWidth = 0;
        this.mMatchConstraintDefaultHeight = 0;
        this.mMatchConstraintMinWidth = 0;
        this.mMatchConstraintMaxWidth = 0;
        this.mMatchConstraintMinHeight = 0;
        this.mMatchConstraintMaxHeight = 0;
        this.mLeft = new ConstraintAnchor(this, Type.LEFT);
        this.mTop = new ConstraintAnchor(this, Type.TOP);
        this.mRight = new ConstraintAnchor(this, Type.RIGHT);
        this.mBottom = new ConstraintAnchor(this, Type.BOTTOM);
        this.mBaseline = new ConstraintAnchor(this, Type.BASELINE);
        this.mCenterX = new ConstraintAnchor(this, Type.CENTER_X);
        this.mCenterY = new ConstraintAnchor(this, Type.CENTER_Y);
        this.mCenter = new ConstraintAnchor(this, Type.CENTER);
        this.mAnchors = new ArrayList();
        this.mParent = null;
        this.mWidth = 0;
        this.mHeight = 0;
        this.mDimensionRatio = 0.0f;
        this.mDimensionRatioSide = -1;
        this.mSolverLeft = 0;
        this.mSolverTop = 0;
        this.mSolverRight = 0;
        this.mSolverBottom = 0;
        this.mX = 0;
        this.mY = 0;
        this.mDrawX = 0;
        this.mDrawY = 0;
        this.mDrawWidth = 0;
        this.mDrawHeight = 0;
        this.mOffsetX = 0;
        this.mOffsetY = 0;
        this.mBaselineDistance = 0;
        this.mHorizontalBiasPercent = DEFAULT_BIAS;
        this.mVerticalBiasPercent = DEFAULT_BIAS;
        this.mHorizontalDimensionBehaviour = DimensionBehaviour.FIXED;
        this.mVerticalDimensionBehaviour = DimensionBehaviour.FIXED;
        this.mContainerItemSkip = 0;
        this.mVisibility = 0;
        this.mDebugName = null;
        this.mType = null;
        this.mHorizontalChainStyle = 0;
        this.mVerticalChainStyle = 0;
        this.mHorizontalWeight = 0.0f;
        this.mVerticalWeight = 0.0f;
        this.mHorizontalNextWidget = null;
        this.mVerticalNextWidget = null;
        this.mX = x;
        this.mY = y;
        this.mWidth = width;
        this.mHeight = height;
        addAnchors();
        forceUpdateDrawPosition();
    }

    public ConstraintWidget(int width, int height) {
        this(0, 0, width, height);
    }

    public void resetSolverVariables(Cache cache) {
        this.mLeft.resetSolverVariable(cache);
        this.mTop.resetSolverVariable(cache);
        this.mRight.resetSolverVariable(cache);
        this.mBottom.resetSolverVariable(cache);
        this.mBaseline.resetSolverVariable(cache);
        this.mCenter.resetSolverVariable(cache);
        this.mCenterX.resetSolverVariable(cache);
        this.mCenterY.resetSolverVariable(cache);
    }

    public void resetGroups() {
        int numAnchors = this.mAnchors.size();
        for (int i = 0; i < numAnchors; i++) {
            ((ConstraintAnchor) this.mAnchors.get(i)).mGroup = ConstraintAnchor.ANY_GROUP;
        }
    }

    private void addAnchors() {
        this.mAnchors.add(this.mLeft);
        this.mAnchors.add(this.mTop);
        this.mAnchors.add(this.mRight);
        this.mAnchors.add(this.mBottom);
        this.mAnchors.add(this.mCenterX);
        this.mAnchors.add(this.mCenterY);
        this.mAnchors.add(this.mBaseline);
    }

    public boolean isRoot() {
        return this.mParent == null;
    }

    public boolean isRootContainer() {
        return (this instanceof ConstraintWidgetContainer) && (this.mParent == null || !(this.mParent instanceof ConstraintWidgetContainer));
    }

    public boolean isInsideConstraintLayout() {
        ConstraintWidget widget = getParent();
        if (widget == null) {
            return false;
        }
        while (widget != null) {
            if (widget instanceof ConstraintWidgetContainer) {
                return true;
            }
            widget = widget.getParent();
        }
        return false;
    }

    public boolean hasAncestor(ConstraintWidget widget) {
        ConstraintWidget parent = getParent();
        if (parent == widget) {
            return true;
        }
        if (parent == widget.getParent()) {
            return false;
        }
        while (parent != null) {
            if (parent == widget) {
                return true;
            }
            if (parent == widget.getParent()) {
                return true;
            }
            parent = parent.getParent();
        }
        return false;
    }

    public WidgetContainer getRootWidgetContainer() {
        ConstraintWidget root = this;
        while (root.getParent() != null) {
            root = root.getParent();
        }
        if (root instanceof WidgetContainer) {
            return (WidgetContainer) root;
        }
        return null;
    }

    public ConstraintWidget getParent() {
        return this.mParent;
    }

    public void setParent(ConstraintWidget widget) {
        this.mParent = widget;
    }

    public String getType() {
        return this.mType;
    }

    public void setType(String type) {
        this.mType = type;
    }

    public void setVisibility(int visibility) {
        this.mVisibility = visibility;
    }

    public int getVisibility() {
        return this.mVisibility;
    }

    public String getDebugName() {
        return this.mDebugName;
    }

    public void setDebugName(String name) {
        this.mDebugName = name;
    }

    public void setDebugSolverName(LinearSystem system, String name) {
        this.mDebugName = name;
        SolverVariable left = system.createObjectVariable(this.mLeft);
        SolverVariable top = system.createObjectVariable(this.mTop);
        SolverVariable right = system.createObjectVariable(this.mRight);
        SolverVariable bottom = system.createObjectVariable(this.mBottom);
        left.setName(name + ".left");
        top.setName(name + ".top");
        right.setName(name + ".right");
        bottom.setName(name + ".bottom");
        if (this.mBaselineDistance > 0) {
            system.createObjectVariable(this.mBaseline).setName(name + ".baseline");
        }
    }

    public String toString() {
        return (this.mType != null ? "type: " + this.mType + " " : "") + (this.mDebugName != null ? "id: " + this.mDebugName + " " : "") + "(" + this.mX + ", " + this.mY + ") - (" + this.mWidth + " x " + this.mHeight + ")" + " wrap: (" + this.mWrapWidth + " x " + this.mWrapHeight + ")";
    }

    int getInternalDrawX() {
        return this.mDrawX;
    }

    int getInternalDrawY() {
        return this.mDrawY;
    }

    public int getInternalDrawRight() {
        return this.mDrawX + this.mDrawWidth;
    }

    public int getInternalDrawBottom() {
        return this.mDrawY + this.mDrawHeight;
    }

    public int getX() {
        return this.mX;
    }

    public int getY() {
        return this.mY;
    }

    public int getWidth() {
        if (this.mVisibility == 8) {
            return 0;
        }
        return this.mWidth;
    }

    public int getOptimizerWrapWidth() {
        int w = this.mWidth;
        if (this.mHorizontalDimensionBehaviour != DimensionBehaviour.MATCH_CONSTRAINT) {
            return w;
        }
        if (this.mMatchConstraintDefaultWidth == 1) {
            w = Math.max(this.mMatchConstraintMinWidth, w);
        } else if (this.mMatchConstraintMinWidth > 0) {
            w = this.mMatchConstraintMinWidth;
            this.mWidth = w;
        } else {
            w = 0;
        }
        if (this.mMatchConstraintMaxWidth <= 0 || this.mMatchConstraintMaxWidth >= w) {
            return w;
        }
        return this.mMatchConstraintMaxWidth;
    }

    public int getOptimizerWrapHeight() {
        int h = this.mHeight;
        if (this.mVerticalDimensionBehaviour != DimensionBehaviour.MATCH_CONSTRAINT) {
            return h;
        }
        if (this.mMatchConstraintDefaultHeight == 1) {
            h = Math.max(this.mMatchConstraintMinHeight, h);
        } else if (this.mMatchConstraintMinHeight > 0) {
            h = this.mMatchConstraintMinHeight;
            this.mHeight = h;
        } else {
            h = 0;
        }
        if (this.mMatchConstraintMaxHeight <= 0 || this.mMatchConstraintMaxHeight >= h) {
            return h;
        }
        return this.mMatchConstraintMaxHeight;
    }

    public int getWrapWidth() {
        return this.mWrapWidth;
    }

    public int getHeight() {
        if (this.mVisibility == 8) {
            return 0;
        }
        return this.mHeight;
    }

    public int getWrapHeight() {
        return this.mWrapHeight;
    }

    public int getDrawX() {
        return this.mDrawX + this.mOffsetX;
    }

    public int getDrawY() {
        return this.mDrawY + this.mOffsetY;
    }

    public int getDrawWidth() {
        return this.mDrawWidth;
    }

    public int getDrawHeight() {
        return this.mDrawHeight;
    }

    public int getDrawBottom() {
        return getDrawY() + this.mDrawHeight;
    }

    public int getDrawRight() {
        return getDrawX() + this.mDrawWidth;
    }

    protected int getRootX() {
        return this.mX + this.mOffsetX;
    }

    protected int getRootY() {
        return this.mY + this.mOffsetY;
    }

    public int getMinWidth() {
        return this.mMinWidth;
    }

    public int getMinHeight() {
        return this.mMinHeight;
    }

    public int getLeft() {
        return getX();
    }

    public int getTop() {
        return getY();
    }

    public int getRight() {
        return getX() + this.mWidth;
    }

    public int getBottom() {
        return getY() + this.mHeight;
    }

    public float getHorizontalBiasPercent() {
        return this.mHorizontalBiasPercent;
    }

    public float getVerticalBiasPercent() {
        return this.mVerticalBiasPercent;
    }

    public boolean hasBaseline() {
        return this.mBaselineDistance > 0;
    }

    public int getBaselineDistance() {
        return this.mBaselineDistance;
    }

    public Object getCompanionWidget() {
        return this.mCompanionWidget;
    }

    public ArrayList<ConstraintAnchor> getAnchors() {
        return this.mAnchors;
    }

    public void setX(int x) {
        this.mX = x;
    }

    public void setY(int y) {
        this.mY = y;
    }

    public void setOrigin(int x, int y) {
        this.mX = x;
        this.mY = y;
    }

    public void setOffset(int x, int y) {
        this.mOffsetX = x;
        this.mOffsetY = y;
    }

    public void setGoneMargin(Type type, int goneMargin) {
        switch (type) {
            case LEFT:
                this.mLeft.mGoneMargin = goneMargin;
                return;
            case TOP:
                this.mTop.mGoneMargin = goneMargin;
                return;
            case RIGHT:
                this.mRight.mGoneMargin = goneMargin;
                return;
            case BOTTOM:
                this.mBottom.mGoneMargin = goneMargin;
                return;
            default:
                return;
        }
    }

    public void updateDrawPosition() {
        int left = this.mX;
        int top = this.mY;
        int right = this.mX + this.mWidth;
        int bottom = this.mY + this.mHeight;
        this.mDrawX = left;
        this.mDrawY = top;
        this.mDrawWidth = right - left;
        this.mDrawHeight = bottom - top;
    }

    public void forceUpdateDrawPosition() {
        int left = this.mX;
        int top = this.mY;
        int right = this.mX + this.mWidth;
        int bottom = this.mY + this.mHeight;
        this.mDrawX = left;
        this.mDrawY = top;
        this.mDrawWidth = right - left;
        this.mDrawHeight = bottom - top;
    }

    public void setDrawOrigin(int x, int y) {
        this.mDrawX = x - this.mOffsetX;
        this.mDrawY = y - this.mOffsetY;
        this.mX = this.mDrawX;
        this.mY = this.mDrawY;
    }

    public void setDrawX(int x) {
        this.mDrawX = x - this.mOffsetX;
        this.mX = this.mDrawX;
    }

    public void setDrawY(int y) {
        this.mDrawY = y - this.mOffsetY;
        this.mY = this.mDrawY;
    }

    public void setDrawWidth(int drawWidth) {
        this.mDrawWidth = drawWidth;
    }

    public void setDrawHeight(int drawHeight) {
        this.mDrawHeight = drawHeight;
    }

    public void setWidth(int w) {
        this.mWidth = w;
        if (this.mWidth < this.mMinWidth) {
            this.mWidth = this.mMinWidth;
        }
    }

    public void setHeight(int h) {
        this.mHeight = h;
        if (this.mHeight < this.mMinHeight) {
            this.mHeight = this.mMinHeight;
        }
    }

    public void setHorizontalMatchStyle(int horizontalMatchStyle, int min, int max) {
        this.mMatchConstraintDefaultWidth = horizontalMatchStyle;
        this.mMatchConstraintMinWidth = min;
        this.mMatchConstraintMaxWidth = max;
    }

    public void setVerticalMatchStyle(int verticalMatchStyle, int min, int max) {
        this.mMatchConstraintDefaultHeight = verticalMatchStyle;
        this.mMatchConstraintMinHeight = min;
        this.mMatchConstraintMaxHeight = max;
    }

    public void setDimensionRatio(String ratio) {
        if (ratio == null || ratio.length() == 0) {
            this.mDimensionRatio = 0.0f;
            return;
        }
        int dimensionRatioSide = -1;
        float dimensionRatio = 0.0f;
        int len = ratio.length();
        int commaIndex = ratio.indexOf(44);
        if (commaIndex <= 0 || commaIndex >= len - 1) {
            commaIndex = 0;
        } else {
            String dimension = ratio.substring(0, commaIndex);
            if (dimension.equalsIgnoreCase("W")) {
                dimensionRatioSide = 0;
            } else if (dimension.equalsIgnoreCase("H")) {
                dimensionRatioSide = 1;
            }
            commaIndex++;
        }
        int colonIndex = ratio.indexOf(58);
        if (colonIndex < 0 || colonIndex >= len - 1) {
            String r = ratio.substring(commaIndex);
            if (r.length() > 0) {
                try {
                    dimensionRatio = Float.parseFloat(r);
                } catch (NumberFormatException e) {
                }
            }
        } else {
            String nominator = ratio.substring(commaIndex, colonIndex);
            String denominator = ratio.substring(colonIndex + 1);
            if (nominator.length() > 0 && denominator.length() > 0) {
                try {
                    float nominatorValue = Float.parseFloat(nominator);
                    float denominatorValue = Float.parseFloat(denominator);
                    if (nominatorValue > 0.0f && denominatorValue > 0.0f) {
                        dimensionRatio = dimensionRatioSide == 1 ? Math.abs(denominatorValue / nominatorValue) : Math.abs(nominatorValue / denominatorValue);
                    }
                } catch (NumberFormatException e2) {
                }
            }
        }
        if (dimensionRatio > 0.0f) {
            this.mDimensionRatio = dimensionRatio;
            this.mDimensionRatioSide = dimensionRatioSide;
        }
    }

    public void setDimensionRatio(float ratio, int dimensionRatioSide) {
        this.mDimensionRatio = ratio;
        this.mDimensionRatioSide = dimensionRatioSide;
    }

    public float getDimensionRatio() {
        return this.mDimensionRatio;
    }

    public int getDimensionRatioSide() {
        return this.mDimensionRatioSide;
    }

    public void setHorizontalBiasPercent(float horizontalBiasPercent) {
        this.mHorizontalBiasPercent = horizontalBiasPercent;
    }

    public void setVerticalBiasPercent(float verticalBiasPercent) {
        this.mVerticalBiasPercent = verticalBiasPercent;
    }

    public void setMinWidth(int w) {
        if (w < 0) {
            this.mMinWidth = 0;
        } else {
            this.mMinWidth = w;
        }
    }

    public void setMinHeight(int h) {
        if (h < 0) {
            this.mMinHeight = 0;
        } else {
            this.mMinHeight = h;
        }
    }

    public void setWrapWidth(int w) {
        this.mWrapWidth = w;
    }

    public void setWrapHeight(int h) {
        this.mWrapHeight = h;
    }

    public void setDimension(int w, int h) {
        this.mWidth = w;
        if (this.mWidth < this.mMinWidth) {
            this.mWidth = this.mMinWidth;
        }
        this.mHeight = h;
        if (this.mHeight < this.mMinHeight) {
            this.mHeight = this.mMinHeight;
        }
    }

    public void setFrame(int left, int top, int right, int bottom) {
        int w = right - left;
        int h = bottom - top;
        this.mX = left;
        this.mY = top;
        if (this.mVisibility == 8) {
            this.mWidth = 0;
            this.mHeight = 0;
            return;
        }
        if (this.mHorizontalDimensionBehaviour == DimensionBehaviour.FIXED && w < this.mWidth) {
            w = this.mWidth;
        }
        if (this.mVerticalDimensionBehaviour == DimensionBehaviour.FIXED && h < this.mHeight) {
            h = this.mHeight;
        }
        this.mWidth = w;
        this.mHeight = h;
        if (this.mHeight < this.mMinHeight) {
            this.mHeight = this.mMinHeight;
        }
        if (this.mWidth < this.mMinWidth) {
            this.mWidth = this.mMinWidth;
        }
    }

    public void setHorizontalDimension(int left, int right) {
        this.mX = left;
        this.mWidth = right - left;
        if (this.mWidth < this.mMinWidth) {
            this.mWidth = this.mMinWidth;
        }
    }

    public void setVerticalDimension(int top, int bottom) {
        this.mY = top;
        this.mHeight = bottom - top;
        if (this.mHeight < this.mMinHeight) {
            this.mHeight = this.mMinHeight;
        }
    }

    public void setBaselineDistance(int baseline) {
        this.mBaselineDistance = baseline;
    }

    public void setCompanionWidget(Object companion) {
        this.mCompanionWidget = companion;
    }

    public void setContainerItemSkip(int skip) {
        if (skip >= 0) {
            this.mContainerItemSkip = skip;
        } else {
            this.mContainerItemSkip = 0;
        }
    }

    public int getContainerItemSkip() {
        return this.mContainerItemSkip;
    }

    public void setHorizontalWeight(float horizontalWeight) {
        this.mHorizontalWeight = horizontalWeight;
    }

    public void setVerticalWeight(float verticalWeight) {
        this.mVerticalWeight = verticalWeight;
    }

    public void setHorizontalChainStyle(int horizontalChainStyle) {
        this.mHorizontalChainStyle = horizontalChainStyle;
    }

    public int getHorizontalChainStyle() {
        return this.mHorizontalChainStyle;
    }

    public void setVerticalChainStyle(int verticalChainStyle) {
        this.mVerticalChainStyle = verticalChainStyle;
    }

    public int getVerticalChainStyle() {
        return this.mVerticalChainStyle;
    }

    public void connectedTo(ConstraintWidget source) {
    }

    public void immediateConnect(Type startType, ConstraintWidget target, Type endType, int margin, int goneMargin) {
        getAnchor(startType).connect(target.getAnchor(endType), margin, goneMargin, Strength.STRONG, 0, true);
    }

    public void connect(ConstraintAnchor from, ConstraintAnchor to, int margin, int creator) {
        connect(from, to, margin, Strength.STRONG, creator);
    }

    public void connect(ConstraintAnchor from, ConstraintAnchor to, int margin) {
        connect(from, to, margin, Strength.STRONG, 0);
    }

    public void connect(ConstraintAnchor from, ConstraintAnchor to, int margin, Strength strength, int creator) {
        if (from.getOwner() == this) {
            connect(from.getType(), to.getOwner(), to.getType(), margin, strength, creator);
        }
    }

    public void connect(Type constraintFrom, ConstraintWidget target, Type constraintTo, int margin) {
        connect(constraintFrom, target, constraintTo, margin, Strength.STRONG);
    }

    public void connect(Type constraintFrom, ConstraintWidget target, Type constraintTo) {
        connect(constraintFrom, target, constraintTo, 0, Strength.STRONG);
    }

    public void connect(Type constraintFrom, ConstraintWidget target, Type constraintTo, int margin, Strength strength) {
        connect(constraintFrom, target, constraintTo, margin, strength, 0);
    }

    public void connect(Type constraintFrom, ConstraintWidget target, Type constraintTo, int margin, Strength strength, int creator) {
        ConstraintAnchor left;
        ConstraintAnchor right;
        ConstraintAnchor top;
        ConstraintAnchor bottom;
        if (constraintFrom == Type.CENTER) {
            if (constraintTo == Type.CENTER) {
                left = getAnchor(Type.LEFT);
                right = getAnchor(Type.RIGHT);
                top = getAnchor(Type.TOP);
                bottom = getAnchor(Type.BOTTOM);
                boolean centerX = false;
                boolean centerY = false;
                if ((left == null || !left.isConnected()) && (right == null || !right.isConnected())) {
                    connect(Type.LEFT, target, Type.LEFT, 0, strength, creator);
                    connect(Type.RIGHT, target, Type.RIGHT, 0, strength, creator);
                    centerX = true;
                }
                if ((top == null || !top.isConnected()) && (bottom == null || !bottom.isConnected())) {
                    connect(Type.TOP, target, Type.TOP, 0, strength, creator);
                    connect(Type.BOTTOM, target, Type.BOTTOM, 0, strength, creator);
                    centerY = true;
                }
                if (centerX && centerY) {
                    getAnchor(Type.CENTER).connect(target.getAnchor(Type.CENTER), 0, creator);
                } else if (centerX) {
                    getAnchor(Type.CENTER_X).connect(target.getAnchor(Type.CENTER_X), 0, creator);
                } else if (centerY) {
                    getAnchor(Type.CENTER_Y).connect(target.getAnchor(Type.CENTER_Y), 0, creator);
                }
            } else if (constraintTo == Type.LEFT || constraintTo == Type.RIGHT) {
                connect(Type.LEFT, target, constraintTo, 0, strength, creator);
                connect(Type.RIGHT, target, constraintTo, 0, strength, creator);
                getAnchor(Type.CENTER).connect(target.getAnchor(constraintTo), 0, creator);
            } else if (constraintTo == Type.TOP || constraintTo == Type.BOTTOM) {
                connect(Type.TOP, target, constraintTo, 0, strength, creator);
                connect(Type.BOTTOM, target, constraintTo, 0, strength, creator);
                getAnchor(Type.CENTER).connect(target.getAnchor(constraintTo), 0, creator);
            }
        } else if (constraintFrom == Type.CENTER_X && (constraintTo == Type.LEFT || constraintTo == Type.RIGHT)) {
            left = getAnchor(Type.LEFT);
            targetAnchor = target.getAnchor(constraintTo);
            right = getAnchor(Type.RIGHT);
            left.connect(targetAnchor, 0, creator);
            right.connect(targetAnchor, 0, creator);
            getAnchor(Type.CENTER_X).connect(targetAnchor, 0, creator);
        } else if (constraintFrom == Type.CENTER_Y && (constraintTo == Type.TOP || constraintTo == Type.BOTTOM)) {
            targetAnchor = target.getAnchor(constraintTo);
            getAnchor(Type.TOP).connect(targetAnchor, 0, creator);
            getAnchor(Type.BOTTOM).connect(targetAnchor, 0, creator);
            getAnchor(Type.CENTER_Y).connect(targetAnchor, 0, creator);
        } else if (constraintFrom == Type.CENTER_X && constraintTo == Type.CENTER_X) {
            getAnchor(Type.LEFT).connect(target.getAnchor(Type.LEFT), 0, creator);
            getAnchor(Type.RIGHT).connect(target.getAnchor(Type.RIGHT), 0, creator);
            getAnchor(Type.CENTER_X).connect(target.getAnchor(constraintTo), 0, creator);
        } else if (constraintFrom == Type.CENTER_Y && constraintTo == Type.CENTER_Y) {
            getAnchor(Type.TOP).connect(target.getAnchor(Type.TOP), 0, creator);
            getAnchor(Type.BOTTOM).connect(target.getAnchor(Type.BOTTOM), 0, creator);
            getAnchor(Type.CENTER_Y).connect(target.getAnchor(constraintTo), 0, creator);
        } else {
            ConstraintAnchor fromAnchor = getAnchor(constraintFrom);
            ConstraintAnchor toAnchor = target.getAnchor(constraintTo);
            if (fromAnchor.isValidConnection(toAnchor)) {
                if (constraintFrom == Type.BASELINE) {
                    top = getAnchor(Type.TOP);
                    bottom = getAnchor(Type.BOTTOM);
                    if (top != null) {
                        top.reset();
                    }
                    if (bottom != null) {
                        bottom.reset();
                    }
                    margin = 0;
                } else if (constraintFrom == Type.TOP || constraintFrom == Type.BOTTOM) {
                    ConstraintAnchor baseline = getAnchor(Type.BASELINE);
                    if (baseline != null) {
                        baseline.reset();
                    }
                    center = getAnchor(Type.CENTER);
                    if (center.getTarget() != toAnchor) {
                        center.reset();
                    }
                    opposite = getAnchor(constraintFrom).getOpposite();
                    ConstraintAnchor centerY2 = getAnchor(Type.CENTER_Y);
                    if (centerY2.isConnected()) {
                        opposite.reset();
                        centerY2.reset();
                    }
                } else if (constraintFrom == Type.LEFT || constraintFrom == Type.RIGHT) {
                    center = getAnchor(Type.CENTER);
                    if (center.getTarget() != toAnchor) {
                        center.reset();
                    }
                    opposite = getAnchor(constraintFrom).getOpposite();
                    ConstraintAnchor centerX2 = getAnchor(Type.CENTER_X);
                    if (centerX2.isConnected()) {
                        opposite.reset();
                        centerX2.reset();
                    }
                }
                fromAnchor.connect(toAnchor, margin, strength, creator);
                toAnchor.getOwner().connectedTo(fromAnchor.getOwner());
            }
        }
    }

    public void resetAllConstraints() {
        resetAnchors();
        setVerticalBiasPercent(DEFAULT_BIAS);
        setHorizontalBiasPercent(DEFAULT_BIAS);
        if (!(this instanceof ConstraintWidgetContainer)) {
            if (getHorizontalDimensionBehaviour() == DimensionBehaviour.MATCH_CONSTRAINT) {
                if (getWidth() == getWrapWidth()) {
                    setHorizontalDimensionBehaviour(DimensionBehaviour.WRAP_CONTENT);
                } else if (getWidth() > getMinWidth()) {
                    setHorizontalDimensionBehaviour(DimensionBehaviour.FIXED);
                }
            }
            if (getVerticalDimensionBehaviour() != DimensionBehaviour.MATCH_CONSTRAINT) {
                return;
            }
            if (getHeight() == getWrapHeight()) {
                setVerticalDimensionBehaviour(DimensionBehaviour.WRAP_CONTENT);
            } else if (getHeight() > getMinHeight()) {
                setVerticalDimensionBehaviour(DimensionBehaviour.FIXED);
            }
        }
    }

    public void resetAnchor(ConstraintAnchor anchor) {
        if (getParent() == null || !(getParent() instanceof ConstraintWidgetContainer) || !((ConstraintWidgetContainer) getParent()).handlesInternalConstraints()) {
            ConstraintAnchor left = getAnchor(Type.LEFT);
            ConstraintAnchor right = getAnchor(Type.RIGHT);
            ConstraintAnchor top = getAnchor(Type.TOP);
            ConstraintAnchor bottom = getAnchor(Type.BOTTOM);
            ConstraintAnchor center = getAnchor(Type.CENTER);
            ConstraintAnchor centerX = getAnchor(Type.CENTER_X);
            ConstraintAnchor centerY = getAnchor(Type.CENTER_Y);
            if (anchor == center) {
                if (left.isConnected() && right.isConnected() && left.getTarget() == right.getTarget()) {
                    left.reset();
                    right.reset();
                }
                if (top.isConnected() && bottom.isConnected() && top.getTarget() == bottom.getTarget()) {
                    top.reset();
                    bottom.reset();
                }
                this.mHorizontalBiasPercent = 0.5f;
                this.mVerticalBiasPercent = 0.5f;
            } else if (anchor == centerX) {
                if (left.isConnected() && right.isConnected() && left.getTarget().getOwner() == right.getTarget().getOwner()) {
                    left.reset();
                    right.reset();
                }
                this.mHorizontalBiasPercent = 0.5f;
            } else if (anchor == centerY) {
                if (top.isConnected() && bottom.isConnected() && top.getTarget().getOwner() == bottom.getTarget().getOwner()) {
                    top.reset();
                    bottom.reset();
                }
                this.mVerticalBiasPercent = 0.5f;
            } else if (anchor == left || anchor == right) {
                if (left.isConnected() && left.getTarget() == right.getTarget()) {
                    center.reset();
                }
            } else if ((anchor == top || anchor == bottom) && top.isConnected() && top.getTarget() == bottom.getTarget()) {
                center.reset();
            }
            anchor.reset();
        }
    }

    public void resetAnchors() {
        ConstraintWidget parent = getParent();
        if (parent == null || !(parent instanceof ConstraintWidgetContainer) || !((ConstraintWidgetContainer) getParent()).handlesInternalConstraints()) {
            int mAnchorsSize = this.mAnchors.size();
            for (int i = 0; i < mAnchorsSize; i++) {
                ((ConstraintAnchor) this.mAnchors.get(i)).reset();
            }
        }
    }

    public void resetAnchors(int connectionCreator) {
        ConstraintWidget parent = getParent();
        if (parent == null || !(parent instanceof ConstraintWidgetContainer) || !((ConstraintWidgetContainer) getParent()).handlesInternalConstraints()) {
            int mAnchorsSize = this.mAnchors.size();
            for (int i = 0; i < mAnchorsSize; i++) {
                ConstraintAnchor anchor = (ConstraintAnchor) this.mAnchors.get(i);
                if (connectionCreator == anchor.getConnectionCreator()) {
                    if (anchor.isVerticalAnchor()) {
                        setVerticalBiasPercent(DEFAULT_BIAS);
                    } else {
                        setHorizontalBiasPercent(DEFAULT_BIAS);
                    }
                    anchor.reset();
                }
            }
        }
    }

    public void disconnectWidget(ConstraintWidget widget) {
        ArrayList<ConstraintAnchor> anchors = getAnchors();
        int anchorsSize = anchors.size();
        for (int i = 0; i < anchorsSize; i++) {
            ConstraintAnchor anchor = (ConstraintAnchor) anchors.get(i);
            if (anchor.isConnected() && anchor.getTarget().getOwner() == widget) {
                anchor.reset();
            }
        }
    }

    public void disconnectUnlockedWidget(ConstraintWidget widget) {
        ArrayList<ConstraintAnchor> anchors = getAnchors();
        int anchorsSize = anchors.size();
        for (int i = 0; i < anchorsSize; i++) {
            ConstraintAnchor anchor = (ConstraintAnchor) anchors.get(i);
            if (anchor.isConnected() && anchor.getTarget().getOwner() == widget && anchor.getConnectionCreator() == 2) {
                anchor.reset();
            }
        }
    }

    public ConstraintAnchor getAnchor(Type anchorType) {
        switch (anchorType) {
            case LEFT:
                return this.mLeft;
            case TOP:
                return this.mTop;
            case RIGHT:
                return this.mRight;
            case BOTTOM:
                return this.mBottom;
            case BASELINE:
                return this.mBaseline;
            case CENTER_X:
                return this.mCenterX;
            case CENTER_Y:
                return this.mCenterY;
            case CENTER:
                return this.mCenter;
            default:
                return null;
        }
    }

    public DimensionBehaviour getHorizontalDimensionBehaviour() {
        return this.mHorizontalDimensionBehaviour;
    }

    public DimensionBehaviour getVerticalDimensionBehaviour() {
        return this.mVerticalDimensionBehaviour;
    }

    public void setHorizontalDimensionBehaviour(DimensionBehaviour behaviour) {
        this.mHorizontalDimensionBehaviour = behaviour;
        if (this.mHorizontalDimensionBehaviour == DimensionBehaviour.WRAP_CONTENT) {
            setWidth(this.mWrapWidth);
        }
    }

    public void setVerticalDimensionBehaviour(DimensionBehaviour behaviour) {
        this.mVerticalDimensionBehaviour = behaviour;
        if (this.mVerticalDimensionBehaviour == DimensionBehaviour.WRAP_CONTENT) {
            setHeight(this.mWrapHeight);
        }
    }

    public boolean isInHorizontalChain() {
        if ((this.mLeft.mTarget == null || this.mLeft.mTarget.mTarget != this.mLeft) && (this.mRight.mTarget == null || this.mRight.mTarget.mTarget != this.mRight)) {
            return false;
        }
        return true;
    }

    public ConstraintWidget getHorizontalChainControlWidget() {
        ConstraintWidget found = null;
        if (!isInHorizontalChain()) {
            return null;
        }
        ConstraintWidget tmp = this;
        while (found == null && tmp != null) {
            ConstraintAnchor anchor = tmp.getAnchor(Type.LEFT);
            ConstraintAnchor targetOwner = anchor == null ? null : anchor.getTarget();
            ConstraintWidget target = targetOwner == null ? null : targetOwner.getOwner();
            if (target == getParent()) {
                return tmp;
            }
            ConstraintAnchor targetAnchor = target == null ? null : target.getAnchor(Type.RIGHT).getTarget();
            if (targetAnchor == null || targetAnchor.getOwner() == tmp) {
                tmp = target;
            } else {
                found = tmp;
            }
        }
        return found;
    }

    public boolean isInVerticalChain() {
        if ((this.mTop.mTarget == null || this.mTop.mTarget.mTarget != this.mTop) && (this.mBottom.mTarget == null || this.mBottom.mTarget.mTarget != this.mBottom)) {
            return false;
        }
        return true;
    }

    public ConstraintWidget getVerticalChainControlWidget() {
        ConstraintWidget found = null;
        if (!isInVerticalChain()) {
            return null;
        }
        ConstraintWidget tmp = this;
        while (found == null && tmp != null) {
            ConstraintAnchor anchor = tmp.getAnchor(Type.TOP);
            ConstraintAnchor targetOwner = anchor == null ? null : anchor.getTarget();
            ConstraintWidget target = targetOwner == null ? null : targetOwner.getOwner();
            if (target == getParent()) {
                return tmp;
            }
            ConstraintAnchor targetAnchor = target == null ? null : target.getAnchor(Type.BOTTOM).getTarget();
            if (targetAnchor == null || targetAnchor.getOwner() == tmp) {
                tmp = target;
            } else {
                found = tmp;
            }
        }
        return found;
    }

    public void addToSolver(LinearSystem system) {
        addToSolver(system, ConstraintAnchor.ANY_GROUP);
    }

    public void addToSolver(LinearSystem system, int group) {
        ArrayRow row;
        SolverVariable begin;
        SolverVariable end;
        SolverVariable beginTarget;
        SolverVariable endTarget;
        SolverVariable left = null;
        SolverVariable right = null;
        SolverVariable top = null;
        SolverVariable bottom = null;
        SolverVariable baseline = null;
        if (group == Integer.MAX_VALUE || this.mLeft.mGroup == group) {
            left = system.createObjectVariable(this.mLeft);
        }
        if (group == Integer.MAX_VALUE || this.mRight.mGroup == group) {
            right = system.createObjectVariable(this.mRight);
        }
        if (group == Integer.MAX_VALUE || this.mTop.mGroup == group) {
            top = system.createObjectVariable(this.mTop);
        }
        if (group == Integer.MAX_VALUE || this.mBottom.mGroup == group) {
            bottom = system.createObjectVariable(this.mBottom);
        }
        if (group == Integer.MAX_VALUE || this.mBaseline.mGroup == group) {
            baseline = system.createObjectVariable(this.mBaseline);
        }
        boolean inHorizontalChain = false;
        boolean inVerticalChain = false;
        if (this.mParent != null) {
            if ((this.mLeft.mTarget != null && this.mLeft.mTarget.mTarget == this.mLeft) || (this.mRight.mTarget != null && this.mRight.mTarget.mTarget == this.mRight)) {
                ((ConstraintWidgetContainer) this.mParent).addChain(this, 0);
                inHorizontalChain = true;
            }
            if ((this.mTop.mTarget != null && this.mTop.mTarget.mTarget == this.mTop) || (this.mBottom.mTarget != null && this.mBottom.mTarget.mTarget == this.mBottom)) {
                ((ConstraintWidgetContainer) this.mParent).addChain(this, 1);
                inVerticalChain = true;
            }
            if (this.mParent.getHorizontalDimensionBehaviour() == DimensionBehaviour.WRAP_CONTENT && !inHorizontalChain) {
                if (this.mLeft.mTarget == null || this.mLeft.mTarget.mOwner != this.mParent) {
                    SolverVariable parentLeft = system.createObjectVariable(this.mParent.mLeft);
                    row = system.createRow();
                    row.createRowGreaterThan(left, parentLeft, system.createSlackVariable(), 0);
                    system.addConstraint(row);
                } else if (this.mLeft.mTarget != null && this.mLeft.mTarget.mOwner == this.mParent) {
                    this.mLeft.setConnectionType(ConnectionType.STRICT);
                }
                if (this.mRight.mTarget == null || this.mRight.mTarget.mOwner != this.mParent) {
                    SolverVariable parentRight = system.createObjectVariable(this.mParent.mRight);
                    row = system.createRow();
                    row.createRowGreaterThan(parentRight, right, system.createSlackVariable(), 0);
                    system.addConstraint(row);
                } else if (this.mRight.mTarget != null && this.mRight.mTarget.mOwner == this.mParent) {
                    this.mRight.setConnectionType(ConnectionType.STRICT);
                }
            }
            if (this.mParent.getVerticalDimensionBehaviour() == DimensionBehaviour.WRAP_CONTENT && !inVerticalChain) {
                if (this.mTop.mTarget == null || this.mTop.mTarget.mOwner != this.mParent) {
                    SolverVariable parentTop = system.createObjectVariable(this.mParent.mTop);
                    row = system.createRow();
                    row.createRowGreaterThan(top, parentTop, system.createSlackVariable(), 0);
                    system.addConstraint(row);
                } else if (this.mTop.mTarget != null && this.mTop.mTarget.mOwner == this.mParent) {
                    this.mTop.setConnectionType(ConnectionType.STRICT);
                }
                if (this.mBottom.mTarget == null || this.mBottom.mTarget.mOwner != this.mParent) {
                    SolverVariable parentBottom = system.createObjectVariable(this.mParent.mBottom);
                    row = system.createRow();
                    row.createRowGreaterThan(parentBottom, bottom, system.createSlackVariable(), 0);
                    system.addConstraint(row);
                } else if (this.mBottom.mTarget != null && this.mBottom.mTarget.mOwner == this.mParent) {
                    this.mBottom.setConnectionType(ConnectionType.STRICT);
                }
            }
        }
        int width = this.mWidth;
        if (width < this.mMinWidth) {
            width = this.mMinWidth;
        }
        int height = this.mHeight;
        if (height < this.mMinHeight) {
            height = this.mMinHeight;
        }
        boolean horizontalDimensionFixed = this.mHorizontalDimensionBehaviour != DimensionBehaviour.MATCH_CONSTRAINT;
        boolean verticalDimensionFixed = this.mVerticalDimensionBehaviour != DimensionBehaviour.MATCH_CONSTRAINT;
        if (!(horizontalDimensionFixed || this.mLeft == null || this.mRight == null || (this.mLeft.mTarget != null && this.mRight.mTarget != null))) {
            horizontalDimensionFixed = true;
        }
        if (!(verticalDimensionFixed || this.mTop == null || this.mBottom == null || ((this.mTop.mTarget != null && this.mBottom.mTarget != null) || (this.mBaselineDistance != 0 && (this.mBaseline == null || (this.mTop.mTarget != null && this.mBaseline.mTarget != null)))))) {
            verticalDimensionFixed = true;
        }
        boolean useRatio = false;
        int dimensionRatioSide = this.mDimensionRatioSide;
        float dimensionRatio = this.mDimensionRatio;
        if (this.mDimensionRatio > 0.0f && this.mVisibility != 8) {
            if (this.mHorizontalDimensionBehaviour == DimensionBehaviour.MATCH_CONSTRAINT && this.mVerticalDimensionBehaviour == DimensionBehaviour.MATCH_CONSTRAINT) {
                useRatio = true;
                if (horizontalDimensionFixed && !verticalDimensionFixed) {
                    dimensionRatioSide = 0;
                } else if (!horizontalDimensionFixed && verticalDimensionFixed) {
                    dimensionRatioSide = 1;
                    if (this.mDimensionRatioSide == -1) {
                        dimensionRatio = 1.0f / dimensionRatio;
                    }
                }
            } else if (this.mHorizontalDimensionBehaviour == DimensionBehaviour.MATCH_CONSTRAINT) {
                dimensionRatioSide = 0;
                width = (int) (((float) this.mHeight) * dimensionRatio);
                horizontalDimensionFixed = true;
            } else if (this.mVerticalDimensionBehaviour == DimensionBehaviour.MATCH_CONSTRAINT) {
                dimensionRatioSide = 1;
                if (this.mDimensionRatioSide == -1) {
                    dimensionRatio = 1.0f / dimensionRatio;
                }
                height = (int) (((float) this.mWidth) * dimensionRatio);
                verticalDimensionFixed = true;
            }
        }
        boolean useHorizontalRatio = useRatio && (dimensionRatioSide == 0 || dimensionRatioSide == -1);
        boolean wrapContent = this.mHorizontalDimensionBehaviour == DimensionBehaviour.WRAP_CONTENT && (this instanceof ConstraintWidgetContainer);
        if (this.mHorizontalResolution != 2 && (group == Integer.MAX_VALUE || (this.mLeft.mGroup == group && this.mRight.mGroup == group))) {
            if (!useHorizontalRatio || this.mLeft.mTarget == null || this.mRight.mTarget == null) {
                applyConstraints(system, wrapContent, horizontalDimensionFixed, this.mLeft, this.mRight, this.mX, this.mX + width, width, this.mMinWidth, this.mHorizontalBiasPercent, useHorizontalRatio, inHorizontalChain, this.mMatchConstraintDefaultWidth, this.mMatchConstraintMinWidth, this.mMatchConstraintMaxWidth);
            } else {
                begin = system.createObjectVariable(this.mLeft);
                end = system.createObjectVariable(this.mRight);
                beginTarget = system.createObjectVariable(this.mLeft.getTarget());
                endTarget = system.createObjectVariable(this.mRight.getTarget());
                system.addGreaterThan(begin, beginTarget, this.mLeft.getMargin(), 3);
                system.addLowerThan(end, endTarget, this.mRight.getMargin() * -1, 3);
                if (!inHorizontalChain) {
                    system.addCentering(begin, beginTarget, this.mLeft.getMargin(), this.mHorizontalBiasPercent, endTarget, end, this.mRight.getMargin(), 4);
                }
            }
        }
        if (this.mVerticalResolution != 2) {
            wrapContent = this.mVerticalDimensionBehaviour == DimensionBehaviour.WRAP_CONTENT && (this instanceof ConstraintWidgetContainer);
            boolean useVerticalRatio = useRatio && (dimensionRatioSide == 1 || dimensionRatioSide == -1);
            if (this.mBaselineDistance > 0) {
                ConstraintAnchor endAnchor = this.mBottom;
                if (group == Integer.MAX_VALUE || (this.mBottom.mGroup == group && this.mBaseline.mGroup == group)) {
                    system.addEquality(baseline, top, getBaselineDistance(), 5);
                }
                int originalHeight = height;
                if (this.mBaseline.mTarget != null) {
                    height = this.mBaselineDistance;
                    endAnchor = this.mBaseline;
                }
                if (group == Integer.MAX_VALUE || (this.mTop.mGroup == group && endAnchor.mGroup == group)) {
                    if (!useVerticalRatio || this.mTop.mTarget == null || this.mBottom.mTarget == null) {
                        applyConstraints(system, wrapContent, verticalDimensionFixed, this.mTop, endAnchor, this.mY, this.mY + height, height, this.mMinHeight, this.mVerticalBiasPercent, useVerticalRatio, inVerticalChain, this.mMatchConstraintDefaultHeight, this.mMatchConstraintMinHeight, this.mMatchConstraintMaxHeight);
                        system.addEquality(bottom, top, originalHeight, 5);
                    } else {
                        begin = system.createObjectVariable(this.mTop);
                        end = system.createObjectVariable(this.mBottom);
                        beginTarget = system.createObjectVariable(this.mTop.getTarget());
                        endTarget = system.createObjectVariable(this.mBottom.getTarget());
                        system.addGreaterThan(begin, beginTarget, this.mTop.getMargin(), 3);
                        system.addLowerThan(end, endTarget, this.mBottom.getMargin() * -1, 3);
                        if (!inVerticalChain) {
                            system.addCentering(begin, beginTarget, this.mTop.getMargin(), this.mVerticalBiasPercent, endTarget, end, this.mBottom.getMargin(), 4);
                        }
                    }
                }
            } else if (group == Integer.MAX_VALUE || (this.mTop.mGroup == group && this.mBottom.mGroup == group)) {
                if (!useVerticalRatio || this.mTop.mTarget == null || this.mBottom.mTarget == null) {
                    applyConstraints(system, wrapContent, verticalDimensionFixed, this.mTop, this.mBottom, this.mY, this.mY + height, height, this.mMinHeight, this.mVerticalBiasPercent, useVerticalRatio, inVerticalChain, this.mMatchConstraintDefaultHeight, this.mMatchConstraintMinHeight, this.mMatchConstraintMaxHeight);
                } else {
                    begin = system.createObjectVariable(this.mTop);
                    end = system.createObjectVariable(this.mBottom);
                    beginTarget = system.createObjectVariable(this.mTop.getTarget());
                    endTarget = system.createObjectVariable(this.mBottom.getTarget());
                    system.addGreaterThan(begin, beginTarget, this.mTop.getMargin(), 3);
                    system.addLowerThan(end, endTarget, this.mBottom.getMargin() * -1, 3);
                    if (!inVerticalChain) {
                        system.addCentering(begin, beginTarget, this.mTop.getMargin(), this.mVerticalBiasPercent, endTarget, end, this.mBottom.getMargin(), 4);
                    }
                }
            }
            if (useRatio) {
                row = system.createRow();
                if (group != Integer.MAX_VALUE && (this.mLeft.mGroup != group || this.mRight.mGroup != group)) {
                    return;
                }
                if (dimensionRatioSide == 0) {
                    system.addConstraint(row.createRowDimensionRatio(right, left, bottom, top, dimensionRatio));
                } else if (dimensionRatioSide == 1) {
                    system.addConstraint(row.createRowDimensionRatio(bottom, top, right, left, dimensionRatio));
                } else {
                    if (this.mMatchConstraintMinWidth > 0) {
                        system.addGreaterThan(right, left, this.mMatchConstraintMinWidth, 3);
                    }
                    if (this.mMatchConstraintMinHeight > 0) {
                        system.addGreaterThan(bottom, top, this.mMatchConstraintMinHeight, 3);
                    }
                    row.createRowDimensionRatio(right, left, bottom, top, dimensionRatio);
                    SolverVariable error1 = system.createErrorVariable();
                    SolverVariable error2 = system.createErrorVariable();
                    error1.strength = 4;
                    error2.strength = 4;
                    row.addError(error1, error2);
                    system.addConstraint(row);
                }
            }
        }
    }

    private void applyConstraints(LinearSystem system, boolean wrapContent, boolean dimensionFixed, ConstraintAnchor beginAnchor, ConstraintAnchor endAnchor, int beginPosition, int endPosition, int dimension, int minDimension, float bias, boolean useRatio, boolean inChain, int matchConstraintDefault, int matchMinDimension, int matchMaxDimension) {
        SolverVariable begin = system.createObjectVariable(beginAnchor);
        SolverVariable end = system.createObjectVariable(endAnchor);
        SolverVariable beginTarget = system.createObjectVariable(beginAnchor.getTarget());
        SolverVariable endTarget = system.createObjectVariable(endAnchor.getTarget());
        int beginAnchorMargin = beginAnchor.getMargin();
        int endAnchorMargin = endAnchor.getMargin();
        if (this.mVisibility == 8) {
            dimension = 0;
            dimensionFixed = true;
        }
        if (beginTarget == null && endTarget == null) {
            system.addConstraint(system.createRow().createRowEquals(begin, beginPosition));
            if (!useRatio) {
                if (wrapContent) {
                    system.addConstraint(LinearSystem.createRowEquals(system, end, begin, minDimension, true));
                } else if (dimensionFixed) {
                    system.addConstraint(LinearSystem.createRowEquals(system, end, begin, dimension, false));
                } else {
                    system.addConstraint(system.createRow().createRowEquals(end, endPosition));
                }
            }
        } else if (beginTarget != null && endTarget == null) {
            system.addConstraint(system.createRow().createRowEquals(begin, beginTarget, beginAnchorMargin));
            if (wrapContent) {
                system.addConstraint(LinearSystem.createRowEquals(system, end, begin, minDimension, true));
            } else if (!useRatio) {
                if (dimensionFixed) {
                    system.addConstraint(system.createRow().createRowEquals(end, begin, dimension));
                } else {
                    system.addConstraint(system.createRow().createRowEquals(end, endPosition));
                }
            }
        } else if (beginTarget == null && endTarget != null) {
            system.addConstraint(system.createRow().createRowEquals(end, endTarget, endAnchorMargin * -1));
            if (wrapContent) {
                system.addConstraint(LinearSystem.createRowEquals(system, end, begin, minDimension, true));
            } else if (!useRatio) {
                if (dimensionFixed) {
                    system.addConstraint(system.createRow().createRowEquals(end, begin, dimension));
                } else {
                    system.addConstraint(system.createRow().createRowEquals(begin, beginPosition));
                }
            }
        } else if (dimensionFixed) {
            if (wrapContent) {
                system.addConstraint(LinearSystem.createRowEquals(system, end, begin, minDimension, true));
            } else {
                system.addConstraint(system.createRow().createRowEquals(end, begin, dimension));
            }
            if (beginAnchor.getStrength() != endAnchor.getStrength()) {
                SolverVariable slack;
                ArrayRow row;
                if (beginAnchor.getStrength() == Strength.STRONG) {
                    system.addConstraint(system.createRow().createRowEquals(begin, beginTarget, beginAnchorMargin));
                    slack = system.createSlackVariable();
                    row = system.createRow();
                    row.createRowLowerThan(end, endTarget, slack, endAnchorMargin * -1);
                    system.addConstraint(row);
                    return;
                }
                slack = system.createSlackVariable();
                row = system.createRow();
                row.createRowGreaterThan(begin, beginTarget, slack, beginAnchorMargin);
                system.addConstraint(row);
                system.addConstraint(system.createRow().createRowEquals(end, endTarget, endAnchorMargin * -1));
            } else if (beginTarget == endTarget) {
                system.addConstraint(LinearSystem.createRowCentering(system, begin, beginTarget, 0, 0.5f, endTarget, end, 0, true));
            } else if (!inChain) {
                system.addConstraint(LinearSystem.createRowGreaterThan(system, begin, beginTarget, beginAnchorMargin, beginAnchor.getConnectionType() != ConnectionType.STRICT));
                system.addConstraint(LinearSystem.createRowLowerThan(system, end, endTarget, endAnchorMargin * -1, endAnchor.getConnectionType() != ConnectionType.STRICT));
                system.addConstraint(LinearSystem.createRowCentering(system, begin, beginTarget, beginAnchorMargin, bias, endTarget, end, endAnchorMargin, false));
            }
        } else if (useRatio) {
            system.addGreaterThan(begin, beginTarget, beginAnchorMargin, 3);
            system.addLowerThan(end, endTarget, endAnchorMargin * -1, 3);
            system.addConstraint(LinearSystem.createRowCentering(system, begin, beginTarget, beginAnchorMargin, bias, endTarget, end, endAnchorMargin, true));
        } else if (!inChain) {
            if (matchConstraintDefault == 1) {
                if (matchMinDimension > dimension) {
                    dimension = matchMinDimension;
                }
                if (matchMaxDimension > 0) {
                    if (matchMaxDimension < dimension) {
                        dimension = matchMaxDimension;
                    } else {
                        system.addLowerThan(end, begin, matchMaxDimension, 3);
                    }
                }
                system.addEquality(end, begin, dimension, 3);
                system.addGreaterThan(begin, beginTarget, beginAnchorMargin, 2);
                system.addLowerThan(end, endTarget, -endAnchorMargin, 2);
                system.addCentering(begin, beginTarget, beginAnchorMargin, bias, endTarget, end, endAnchorMargin, 4);
            } else if (matchMinDimension == 0 && matchMaxDimension == 0) {
                system.addConstraint(system.createRow().createRowEquals(begin, beginTarget, beginAnchorMargin));
                system.addConstraint(system.createRow().createRowEquals(end, endTarget, endAnchorMargin * -1));
            } else {
                if (matchMaxDimension > 0) {
                    system.addLowerThan(end, begin, matchMaxDimension, 3);
                }
                system.addGreaterThan(begin, beginTarget, beginAnchorMargin, 2);
                system.addLowerThan(end, endTarget, -endAnchorMargin, 2);
                system.addCentering(begin, beginTarget, beginAnchorMargin, bias, endTarget, end, endAnchorMargin, 4);
            }
        }
    }

    public void updateFromSolver(LinearSystem system, int group) {
        if (group == ConstraintAnchor.ANY_GROUP) {
            setFrame(system.getObjectVariableValue(this.mLeft), system.getObjectVariableValue(this.mTop), system.getObjectVariableValue(this.mRight), system.getObjectVariableValue(this.mBottom));
        } else if (group == -2) {
            setFrame(this.mSolverLeft, this.mSolverTop, this.mSolverRight, this.mSolverBottom);
        } else {
            if (this.mLeft.mGroup == group) {
                this.mSolverLeft = system.getObjectVariableValue(this.mLeft);
            }
            if (this.mTop.mGroup == group) {
                this.mSolverTop = system.getObjectVariableValue(this.mTop);
            }
            if (this.mRight.mGroup == group) {
                this.mSolverRight = system.getObjectVariableValue(this.mRight);
            }
            if (this.mBottom.mGroup == group) {
                this.mSolverBottom = system.getObjectVariableValue(this.mBottom);
            }
        }
    }

    public void updateFromSolver(LinearSystem system) {
        updateFromSolver(system, ConstraintAnchor.ANY_GROUP);
    }
}
