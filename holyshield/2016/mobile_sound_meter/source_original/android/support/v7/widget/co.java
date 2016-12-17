package android.support.v7.widget;

class co {
    private int f1451a;
    private int f1452b;
    private int f1453c;
    private int f1454d;
    private int f1455e;
    private int f1456f;
    private boolean f1457g;
    private boolean f1458h;

    co() {
        this.f1451a = 0;
        this.f1452b = 0;
        this.f1453c = Integer.MIN_VALUE;
        this.f1454d = Integer.MIN_VALUE;
        this.f1455e = 0;
        this.f1456f = 0;
        this.f1457g = false;
        this.f1458h = false;
    }

    public int m2652a() {
        return this.f1451a;
    }

    public void m2653a(int i, int i2) {
        this.f1453c = i;
        this.f1454d = i2;
        this.f1458h = true;
        if (this.f1457g) {
            if (i2 != Integer.MIN_VALUE) {
                this.f1451a = i2;
            }
            if (i != Integer.MIN_VALUE) {
                this.f1452b = i;
                return;
            }
            return;
        }
        if (i != Integer.MIN_VALUE) {
            this.f1451a = i;
        }
        if (i2 != Integer.MIN_VALUE) {
            this.f1452b = i2;
        }
    }

    public void m2654a(boolean z) {
        if (z != this.f1457g) {
            this.f1457g = z;
            if (!this.f1458h) {
                this.f1451a = this.f1455e;
                this.f1452b = this.f1456f;
            } else if (z) {
                this.f1451a = this.f1454d != Integer.MIN_VALUE ? this.f1454d : this.f1455e;
                this.f1452b = this.f1453c != Integer.MIN_VALUE ? this.f1453c : this.f1456f;
            } else {
                this.f1451a = this.f1453c != Integer.MIN_VALUE ? this.f1453c : this.f1455e;
                this.f1452b = this.f1454d != Integer.MIN_VALUE ? this.f1454d : this.f1456f;
            }
        }
    }

    public int m2655b() {
        return this.f1452b;
    }

    public void m2656b(int i, int i2) {
        this.f1458h = false;
        if (i != Integer.MIN_VALUE) {
            this.f1455e = i;
            this.f1451a = i;
        }
        if (i2 != Integer.MIN_VALUE) {
            this.f1456f = i2;
            this.f1452b = i2;
        }
    }

    public int m2657c() {
        return this.f1457g ? this.f1452b : this.f1451a;
    }

    public int m2658d() {
        return this.f1457g ? this.f1451a : this.f1452b;
    }
}
