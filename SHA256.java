import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class SHA256 {
    // Konstanta SHA-256 (nilai-nilai ini berasal dari bagian pecahan dari akar kuadrat dari 8 bilangan prima pertama 2..19)
    private static final int[] K = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    // Nilai hash awal (bagian pecahan dari akar kuadrat dari 8 bilangan prima pertama)
    private static final int[] H = {
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    // Fungsi pembantu untuk operasi bit
    private static int putarKanan(int x, int n) {
        return (x >>> n) | (x << (32 - n));
    }

    // Fungsi pemilihan: jika x maka y, jika tidak maka z
    private static int pilih(int x, int y, int z) {
        return (x & y) ^ (~x & z);
    }

    // Fungsi mayoritas: mengambil nilai yang paling banyak muncul di antara x, y, dan z
    private static int mayoritas(int x, int y, int z) {
        return (x & y) ^ (x & z) ^ (y & z);
    }

    // Fungsi kompresi sigma0
    private static int sigma0(int x) {
        return putarKanan(x, 2) ^ putarKanan(x, 13) ^ putarKanan(x, 22);
    }

    // Fungsi kompresi sigma1
    private static int sigma1(int x) {
        return putarKanan(x, 6) ^ putarKanan(x, 11) ^ putarKanan(x, 25);
    }

    // Fungsi perluasan gamma0
    private static int gamma0(int x) {
        return putarKanan(x, 7) ^ putarKanan(x, 18) ^ (x >>> 3);
    }

    // Fungsi perluasan gamma1
    private static int gamma1(int x) {
        return putarKanan(x, 17) ^ putarKanan(x, 19) ^ (x >>> 10);
    }

    // Fungsi utama SHA-256
    private static byte[] sha256(byte[] pesan) {
        int[] hash = Arrays.copyOf(H, H.length);

        // Padding: menambahkan bit sesuai standar
        int panjangAsli = pesan.length * 8;
        int panjangPadding = ((pesan.length + 8) / 64 + 1) * 64;
        byte[] pesanPadding = Arrays.copyOf(pesan, panjangPadding);
        pesanPadding[pesan.length] = (byte) 0x80; // Menambahkan bit 1 diikuti dengan bit 0

        ByteBuffer buffer = ByteBuffer.wrap(pesanPadding);
        buffer.position(panjangPadding - 8);
        buffer.putLong(panjangAsli); // Menambahkan panjang pesan asli di akhir

        // Memproses setiap blok 512-bit
        for (int i = 0; i < pesanPadding.length; i += 64) {
            int[] w = new int[64];
            
            // Mengubah blok menjadi 16 kata 32-bit
            for (int t = 0; t < 16; t++) {
                w[t] = buffer.getInt(i + t * 4);
            }

            // Memperluas 16 kata menjadi 64 kata
            for (int t = 16; t < 64; t++) {
                w[t] = gamma1(w[t - 2]) + w[t - 7] + gamma0(w[t - 15]) + w[t - 16];
            }

            // Inisialisasi variabel kerja
            int a = hash[0], b = hash[1], c = hash[2], d = hash[3];
            int e = hash[4], f = hash[5], g = hash[6], h = hash[7];

            // Kompresi utama
            for (int t = 0; t < 64; t++) {
                int t1 = h + sigma1(e) + pilih(e, f, g) + K[t] + w[t];
                int t2 = sigma0(a) + mayoritas(a, b, c);
                h = g;
                g = f;
                f = e;
                e = d + t1;
                d = c;
                c = b;
                b = a;
                a = t1 + t2;
            }

            // Menambahkan hasil kompresi ke nilai hash
            hash[0] += a;
            hash[1] += b;
            hash[2] += c;
            hash[3] += d;
            hash[4] += e;
            hash[5] += f;
            hash[6] += g;
            hash[7] += h;
        }

        // Mengkonversi hasil akhir ke byte array
        ByteBuffer hasil = ByteBuffer.allocate(32);
        for (int i = 0; i < 8; i++) {
            hasil.putInt(hash[i]);
        }

        return hasil.array();
    }

    // Mengubah byte array menjadi string hexadecimal
    private static String byteKeHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            hexString.append(String.format("%02x", b));
        }
        return hexString.toString();
    }

    // Metode publik untuk menghasilkan hash SHA-256 dari string
    public static String sha256String(String input) {
        byte[] hash = sha256(input.getBytes(StandardCharsets.UTF_8));
        return byteKeHex(hash);
    }

    // Program utama untuk testing
    public static void main(String[] args) {
        System.out.print("Masukkan teks yang akan di-hash: ");
        String input = new java.util.Scanner(System.in).nextLine();
        System.out.println("Hasil SHA-256: " + sha256String(input));
    }
}