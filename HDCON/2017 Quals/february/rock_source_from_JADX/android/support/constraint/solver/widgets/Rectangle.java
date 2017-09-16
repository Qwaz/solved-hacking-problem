package android.support.constraint.solver.widgets;

public class Rectangle {
    public int height;
    public int width;
    public int f4x;
    public int f5y;

    public void setBounds(int x, int y, int width, int height) {
        this.f4x = x;
        this.f5y = y;
        this.width = width;
        this.height = height;
    }

    void grow(int w, int h) {
        this.f4x -= w;
        this.f5y -= h;
        this.width += w * 2;
        this.height += h * 2;
    }

    boolean intersects(Rectangle bounds) {
        return this.f4x >= bounds.f4x && this.f4x < bounds.f4x + bounds.width && this.f5y >= bounds.f5y && this.f5y < bounds.f5y + bounds.height;
    }

    public boolean contains(int x, int y) {
        return x >= this.f4x && x < this.f4x + this.width && y >= this.f5y && y < this.f5y + this.height;
    }

    public int getCenterX() {
        return (this.f4x + this.width) / 2;
    }

    public int getCenterY() {
        return (this.f5y + this.height) / 2;
    }
}
