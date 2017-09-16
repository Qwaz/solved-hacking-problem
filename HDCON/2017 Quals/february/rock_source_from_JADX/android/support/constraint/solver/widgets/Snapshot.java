package android.support.constraint.solver.widgets;

import android.support.constraint.solver.widgets.ConstraintAnchor.Strength;
import java.util.ArrayList;

public class Snapshot {
    private ArrayList<Connection> mConnections = new ArrayList();
    private int mHeight;
    private int mWidth;
    private int mX;
    private int mY;

    static class Connection {
        private ConstraintAnchor mAnchor;
        private int mCreator;
        private int mMargin;
        private Strength mStrengh;
        private ConstraintAnchor mTarget;

        public Connection(ConstraintAnchor anchor) {
            this.mAnchor = anchor;
            this.mTarget = anchor.getTarget();
            this.mMargin = anchor.getMargin();
            this.mStrengh = anchor.getStrength();
            this.mCreator = anchor.getConnectionCreator();
        }

        public void updateFrom(ConstraintWidget widget) {
            this.mAnchor = widget.getAnchor(this.mAnchor.getType());
            if (this.mAnchor != null) {
                this.mTarget = this.mAnchor.getTarget();
                this.mMargin = this.mAnchor.getMargin();
                this.mStrengh = this.mAnchor.getStrength();
                this.mCreator = this.mAnchor.getConnectionCreator();
                return;
            }
            this.mTarget = null;
            this.mMargin = 0;
            this.mStrengh = Strength.STRONG;
            this.mCreator = 0;
        }

        public void applyTo(ConstraintWidget widget) {
            widget.getAnchor(this.mAnchor.getType()).connect(this.mTarget, this.mMargin, this.mStrengh, this.mCreator);
        }
    }

    public Snapshot(ConstraintWidget widget) {
        this.mX = widget.getX();
        this.mY = widget.getY();
        this.mWidth = widget.getWidth();
        this.mHeight = widget.getHeight();
        ArrayList<ConstraintAnchor> anchors = widget.getAnchors();
        int anchorsSize = anchors.size();
        for (int i = 0; i < anchorsSize; i++) {
            this.mConnections.add(new Connection((ConstraintAnchor) anchors.get(i)));
        }
    }

    public void updateFrom(ConstraintWidget widget) {
        this.mX = widget.getX();
        this.mY = widget.getY();
        this.mWidth = widget.getWidth();
        this.mHeight = widget.getHeight();
        int connections = this.mConnections.size();
        for (int i = 0; i < connections; i++) {
            ((Connection) this.mConnections.get(i)).updateFrom(widget);
        }
    }

    public void applyTo(ConstraintWidget widget) {
        widget.setX(this.mX);
        widget.setY(this.mY);
        widget.setWidth(this.mWidth);
        widget.setHeight(this.mHeight);
        int mConnectionsSize = this.mConnections.size();
        for (int i = 0; i < mConnectionsSize; i++) {
            ((Connection) this.mConnections.get(i)).applyTo(widget);
        }
    }
}
