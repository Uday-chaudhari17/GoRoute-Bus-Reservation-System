function swapCities() {
    const source = document.getElementsByName("source")[0];
    const destination = document.getElementsByName("destination")[0];

    if (!source || !destination) {
        return;
    }

    const current = source.value;
    source.value = destination.value;
    destination.value = current;
}

function updateSeatSummary() {
    const checkedSeats = Array.from(document.querySelectorAll('input[name="seats"]:checked'))
        .map((seat) => seat.value)
        .sort((a, b) => Number(a) - Number(b));
    const summary = document.getElementById("seatSummary");

    if (summary) {
        summary.textContent = checkedSeats.length ? checkedSeats.join(", ") : "None";
    }
}

function togglePaymentFields() {
    const methodSelect = document.getElementById("paymentMethod");
    if (!methodSelect) {
        return;
    }

    const upiFields = document.getElementById("upiFields");
    const cardFields = document.getElementById("cardFields");
    const walletFields = document.getElementById("walletFields");

    [upiFields, cardFields, walletFields].forEach((section) => {
        if (section) {
            section.classList.add("hidden");
        }
    });

    if (methodSelect.value === "UPI" && upiFields) {
        upiFields.classList.remove("hidden");
    }
    if (methodSelect.value === "CARD" && cardFields) {
        cardFields.classList.remove("hidden");
    }
    if (methodSelect.value === "WALLET" && walletFields) {
        walletFields.classList.remove("hidden");
    }
}

document.addEventListener("DOMContentLoaded", () => {
    updateSeatSummary();
    togglePaymentFields();
});
