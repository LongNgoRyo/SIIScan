const express = require('express');
const app = express();
const port = 3000;

app.use(express.json());

app.get('/', (req, res) => {
    res.send('Xin chao cac ban!');
});

app.get('/api/products', (req, res) => {
    const products = [
        { id: 1, name: 'Ao thun', price: 100000 },
        { id: 2, name: 'Quan jeans', price: 250000 },
    ];
    res.json(products);
});

app.post('/api/orders', (req, res) => {
    const { productId, quantity } = req.body;
    res.status(201).json({ message: 'Dat hang thanh cong', productId, quantity });
});

app.listen(port, () => {
    console.log(`Server dang chay tai http://localhost:${port}`);
});
