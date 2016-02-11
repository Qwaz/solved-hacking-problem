/*
 * Decompiled with CFR 0_110.
 */
import java.awt.Point;
import java.awt.image.BufferedImage;
import java.awt.image.RenderedImage;
import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import javax.imageio.ImageIO;

public class Hide {
    protected void steg(String string, String string2) {
        BufferedImage bufferedImage = this.loadImage(string2 + ".png");
        BufferedImage bufferedImage2 = this.steg(string, bufferedImage);
        try {
            ImageIO.write((RenderedImage)bufferedImage2, "png", new File(string2 + "_out.png"));
        }
        catch (IOException var5_5) {
            throw new RuntimeException("Unable to write image!");
        }
    }

    protected BufferedImage steg(String string, BufferedImage bufferedImage) {
        if ((string = "" + string.length() + ":" + string).length() * 8 > bufferedImage.getWidth() * bufferedImage.getHeight()) {
            System.out.println("There won't be enough space to store this message!");
            System.out.println("Message length: " + string.length() + " bytes. " + "Image can hold a maximum of " + bufferedImage.getWidth() * bufferedImage.getHeight() / 8);
            throw new RuntimeException("There won't be enough space to store this message!");
        }
        byte[] arrby = string.getBytes();
        Point point = new Point(0, 0);
        for (int n : arrby) {
            for (int i = 0; i < 8; ++i) {
                if ((n & 128) == 128) {
                    bufferedImage.setRGB(point.x, point.y, this.setLeastSignificantBit(bufferedImage.getRGB(point.x, point.y), true));
                } else {
                    bufferedImage.setRGB(point.x, point.y, this.setLeastSignificantBit(bufferedImage.getRGB(point.x, point.y), false));
                }
                n <<= 1;
                this.movePointer(point, bufferedImage);
            }
        }
        return bufferedImage;
    }

    protected int setLeastSignificantBit(int n, boolean bl) {
        n >>= 1;
        n <<= 1;
        if (bl) {
            ++n;
        }
        return n;
    }

    protected void movePointer(Point point, BufferedImage bufferedImage) {
        if (point.x == bufferedImage.getWidth() - 1) {
            point.x = -1;
            ++point.y;
        }
        ++point.x;
        if (point.y == bufferedImage.getHeight()) {
            throw new RuntimeException("Pointer moved beyond the end of the image");
        }
    }

    private BufferedImage loadImage(String string) {
        try {
            BufferedImage bufferedImage = ImageIO.read(new File(string));
            return bufferedImage;
        }
        catch (IOException var2_3) {
            System.out.println("Unable to load \"" + string + "\"");
            System.exit(0);
            return null;
        }
    }

    public static void main(String[] arrstring) {
        if (arrstring.length < 2) {
            System.out.println("Input Arguments Is Not Valid.");
            System.out.println("Run By 'java -jar Hide.jar `file-path` `message`'");
            return;
        }
        System.out.println("Welcome!\nDecrypt The Image And Capture The Flag!");
        Hide hide = new Hide();
        hide.steg(arrstring[1], arrstring[0]);
    }
}

