import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true, // Removes properties not defined in the DTO
      forbidNonWhitelisted: true, // Rejects the request if non-whitelisted properties are present
      transform: true, // Transforms payloads into class instances
      transformOptions: {
        enableImplicitConversion: true, // Enables automatic type conversion
      },
    }),
  );
  const port = process.env.ATLAS_PORT ?? 3001;
  await app.listen(port);
  console.log(`Cerberus service listening on port ${port}.`);
}
bootstrap();
